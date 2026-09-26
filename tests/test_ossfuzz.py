# Tests for the OSS-Fuzz-style runner. Everything is faked at the subprocess
# boundary so the suite stays offline and deterministic; the assertions are
# about the runner's *logic* (binary discovery, argv, artifact handling,
# error reporting), not about libFuzzer actually finding bugs.
import subprocess
from pathlib import Path

from services import ossfuzz


class FakeProc:
    def __init__(self, rc=0, out="", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _fake_run(monkeypatch, handler):
    """Replace ossfuzz._run with a handler(callable(cmd, cwd, timeout))."""
    calls = []

    def run(cmd, cwd=None, timeout=60):
        calls.append({"cmd": cmd, "cwd": cwd, "timeout": timeout})
        return handler(cmd, len(calls))

    monkeypatch.setattr(ossfuzz, "_run", run)
    return calls


def test_run_requires_clang(monkeypatch):
    monkeypatch.setattr(ossfuzz, "_which", lambda t: None)
    r = ossfuzz.OssFuzzRunner().run(Path("/tmp"))
    assert r["ok"] is False
    assert "clang" in r["error"]


def test_build_failure_is_reported_with_stderr(tmp_path, monkeypatch):
    monkeypatch.setattr(ossfuzz, "_which", lambda t: "/usr/bin/clang")
    _fake_run(
        monkeypatch,
        lambda cmd, n: (1, "", "undefined reference to LLVMFuzzerTestOneInput"),
    )
    r = ossfuzz.OssFuzzRunner().run(tmp_path, build_cmd=["make", "libfuzzer"])
    assert r["ok"] is False
    assert "build failed" in r["error"]
    assert "undefined reference" in r["error"]
    assert any(s.startswith("build:") for s in r["steps"])


def test_missing_fuzz_binary_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(ossfuzz, "_which", lambda t: "/usr/bin/clang")
    _fake_run(monkeypatch, lambda cmd, n: (0, "", ""))
    r = ossfuzz.OssFuzzRunner().run(
        tmp_path, build_cmd=["make", "libfuzzer"], fuzz_bin="nope"
    )
    assert r["ok"] is False
    assert "not found" in r["error"]


def test_binary_discovery_falls_back_to_any_fuzzer_named_file(tmp_path, monkeypatch):
    monkeypatch.setattr(ossfuzz, "_which", lambda t: "/usr/bin/clang")
    (tmp_path / "weird_name_fuzzer").write_text("#!/bin/sh\n", encoding="utf-8")
    calls = _fake_run(monkeypatch, lambda cmd, n: (0, "", ""))
    r = ossfuzz.OssFuzzRunner().run(
        tmp_path, build_cmd=["true"], fuzz_bin="missing_bin"
    )
    # Build ran, then the fallback located the *fuzzer* file and used it.
    assert r["ok"] is True
    assert r["fuzz_bin"] == "weird_name_fuzzer"
    fuzz_call = calls[-1]["cmd"]
    assert "weird_name_fuzzer" in fuzz_call[0]


def test_clean_run_uses_max_total_time_and_no_crashes(tmp_path, monkeypatch):
    monkeypatch.setattr(ossfuzz, "_which", lambda t: "/usr/bin/clang")
    binp = tmp_path / "parse_fuzzer"
    binp.write_text("#!/bin/sh\n", encoding="utf-8")
    calls = _fake_run(monkeypatch, lambda cmd, n: (0, "Done 42 runs in 1s\n", ""))
    r = ossfuzz.OssFuzzRunner().run(tmp_path, build_cmd=["true"], seconds=5)
    assert r["ok"] is True
    assert r["crashes"] == []
    assert r["built"] == "build_cmd"
    # time-capped, not run-capped
    assert "-max_total_time=5" in calls[-1]["cmd"]
    assert not any(c.startswith("-runs=") for c in calls[-1]["cmd"])
    # corpus seeded and passed
    assert any("corpus" in str(c) for c in calls[-1]["cmd"])


def test_runs_flag_overrides_seconds(tmp_path, monkeypatch):
    monkeypatch.setattr(ossfuzz, "_which", lambda t: "/usr/bin/clang")
    (tmp_path / "parse_fuzzer").write_text("#!/bin/sh\n", encoding="utf-8")
    calls = _fake_run(monkeypatch, lambda cmd, n: (0, "", ""))
    ossfuzz.OssFuzzRunner().run(tmp_path, build_cmd=["true"], seconds=5, runs=99)
    assert "-runs=99" in calls[-1]["cmd"]


def test_crash_artifact_is_copied_and_minimized(tmp_path, monkeypatch):
    monkeypatch.setattr(ossfuzz, "_which", lambda t: "/usr/bin/clang")
    (tmp_path / "parse_fuzzer").write_text("#!/bin/sh\n", encoding="utf-8")
    # The fuzzer writes a crash artifact into the repo dir during the run.
    crash_name = "crash-deadbeef"

    def handler(cmd, n):
        if cmd[:2] == ["make", "libfuzzer"] or cmd[0] == "true":
            return 0, "", ""
        # fuzz invocation: simulate libFuzzer writing an artifact + ASan trace
        (tmp_path / crash_name).write_bytes(b"\x01" * 64)
        return (
            1,
            "",
            (
                f"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n"
                f"artifact_prefix='./'; Test unit written to {crash_name}\n"
            ),
        )

    _fake_run(monkeypatch, handler)
    r = ossfuzz.OssFuzzRunner().run(tmp_path, build_cmd=["true"], seconds=1)
    assert r["ok"] is True
    assert len(r["crashes"]) == 1
    c = r["crashes"][0]
    assert c["name"] == crash_name
    # artifact survives repo cleanup: path now points into artifact_dir
    assert c["path"].startswith(r["artifact_dir"])
    assert Path(c["path"]).exists()
    # minimization ran and fell back to the raw bytes (our fake _run ignores it)
    assert c["minimized"]


def test_progress_callback_is_driven(tmp_path, monkeypatch):
    monkeypatch.setattr(ossfuzz, "_which", lambda t: "/usr/bin/clang")
    (tmp_path / "parse_fuzzer").write_text("#!/bin/sh\n", encoding="utf-8")
    _fake_run(monkeypatch, lambda cmd, n: (0, "", ""))
    seen = []
    ossfuzz.OssFuzzRunner(progress=lambda m, p: seen.append((m, p))).run(
        tmp_path, build_cmd=["true"], seconds=1
    )
    assert seen
    assert any("building" in m for m, _ in seen)
    assert any("fuzzing" in m for m, _ in seen)


def test_parse_crashes_extracts_summary_when_no_artifact(tmp_path):
    log = "==1==SUMMARY: AddressSanitizer: stack-buffer-overflow /x.c:5 in parse\n"
    out = ossfuzz._parse_crashes(log, tmp_path)
    assert len(out) == 1
    assert out[0]["name"] == "summary"
    assert out[0]["exists"] is False
    assert "stack-buffer-overflow" in out[0]["summary"]


def test_parse_crashes_empty_log():
    assert ossfuzz._parse_crashes("", Path("/tmp")) == []


def test_run_wrapper_handles_missing_binary(tmp_path):
    rc, _out, err = ossfuzz._run(["definitely-not-a-real-binary-xyz"], tmp_path, 5)
    assert rc == -1
    assert "not found" in err


def test_run_wrapper_handles_timeout(tmp_path):
    with __import__("unittest.mock", fromlist=["patch"]).patch(
        "services.ossfuzz.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="sleep", timeout=1),
    ):
        rc, _o, err = ossfuzz._run(["sleep", "5"], tmp_path, 1)
    assert rc == -1
    assert err == "timeout"


def test_env_includes_sanitizer_trace_settings(monkeypatch):
    env = ossfuzz._env()
    assert "abort_on_error=1" in env["ASAN_OPTIONS"]
    assert "halt_on_error=1" in env["UBSAN_OPTIONS"]
