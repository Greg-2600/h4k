# Tests for the black-box lab fuzzer. Sockets and subprocesses are faked; the
# assertions target the classification logic, the vector builder, and the
# sanitizer block attached to each candidate.
import socket
import subprocess
from pathlib import Path

import pytest
from services.fuzzer import MUTATIONS, LabFuzzer

# --- classification ---------------------------------------------------------


@pytest.mark.parametrize(
    ("rc", "elapsed", "evidence", "baseline", "expected"),
    [
        (4, 0.01, "", True, "resource"),  # refused = service gone
        (3, 0.01, "", True, "teardown"),  # reset = server killed the conn
        (2, 9.0, "", True, "hang"),  # timeout = no response
        (0, 0.01, "HTTP/1.1 500 Internal Server Error", True, "server_error"),
        (0, 0.01, "Exception in thread", True, "server_error"),
        (0, 0.01, "java.lang.NullPointerException", True, "server_error"),
        (0, 0.01, "stack trace", True, "server_error"),
        (0, 0.01, "undefined behavior", True, "server_error"),
        (0, 0.01, "HTTP/1.1 200 OK", True, None),  # normal -> no finding
        (0, 0.01, "HTTP/1.1 200 OK", False, "anomaly"),  # deviant only w/o baseline
        (-1, 0.01, "", True, None),  # unknown error -> no finding
    ],
)
def test_classify(rc, elapsed, evidence, baseline, expected):
    assert LabFuzzer._classify(rc, elapsed, evidence, baseline) == expected


def test_classify_is_static_and_pure():
    # Same inputs must always give the same signal (no hidden state).
    for _ in range(3):
        assert LabFuzzer._classify(3, 0.0, "", True) == "teardown"


# --- vector construction ----------------------------------------------------


def test_build_vector_contains_label_and_payload():
    f = LabFuzzer()
    v = f._build_vector("http://127.0.0.1/", "fmt", b"%n%n")
    assert v.startswith(b"GET / HTTP/1.1\r\nHost: x\r\n")
    assert b"X-Fuzz-fmt: " in v
    assert b"%n%n" in v
    assert v.endswith(b"\r\n\r\n")


def test_build_vector_is_request_smuggling_safe():
    # The label is interpolated raw; a CRLF in it would be a bug in our own
    # fuzzer. Labels come from MUTATIONS (all safe) -- assert that invariant.
    f = LabFuzzer()
    for label, _payload in MUTATIONS:
        assert "\r" not in label and "\n" not in label
        assert b"\r\n" not in label.encode()
        # the built vector has exactly one header terminator
        v = f._build_vector("http://x/", label, b"p")
        assert v.count(b"\r\n\r\n") == 1


# --- _fuzz_http end to end (sockets faked) ----------------------------------


def _stub_transport(monkeypatch, script):
    """Drive _fuzz_http with a scripted sequence of (evidence, rc) results."""
    f = LabFuzzer(mutator=[("v1", b"A"), ("v2", b"B")])
    monkeypatch.setattr(f, "_probe_http", lambda url: True)
    seq = list(script)

    def send(host, port, vector):
        return seq.pop(0) if seq else ("", 0, 0.001)

    monkeypatch.setattr(f, "_send_http", send)
    return f


def test_fuzz_http_reports_only_anomalies(monkeypatch):
    f = _stub_transport(monkeypatch, [("HTTP/1.1 200 OK", 0, 0.001), ("", 3, 0.001)])
    out = f._fuzz_http("127.0.0.1", 8080, "http")
    assert len(out) == 1
    assert out[0]["signal"] == "teardown"
    assert out[0]["host"] == "127.0.0.1"
    assert out[0]["port"] == 8080
    assert out[0]["vector"] == "v2"
    assert out[0]["payload_mutated"] is True
    assert out[0]["repro"].startswith("GET / HTTP/1.1")


def test_fuzz_http_clean_target_yields_nothing(monkeypatch):
    f = _stub_transport(
        monkeypatch, [("HTTP/1.1 200 OK", 0, 0.001), ("HTTP/1.1 200 OK", 0, 0.001)]
    )
    assert f._fuzz_http("127.0.0.1", 80, "http") == []


def test_fuzz_http_attaches_sanitizer_plan_to_candidates(monkeypatch):
    f = _stub_transport(monkeypatch, [("HTTP/1.1 200 OK", 0, 0.001), ("", 3, 0.001)])
    c = f._fuzz_http("127.0.0.1", 8080, "http")[0]
    s = c["sanitizer"]
    assert s["signal"] == "teardown"
    # black-box signal: a replay recipe + candidate classes, never a verdict
    assert s["class"] is None
    assert s["class_candidates"]
    assert "-fsanitize=address,undefined" in s["build_flags"]
    assert "127.0.0.1:8080" in s["replay"]


def test_fuzz_http_progress_reports_each_vector(monkeypatch):
    seen = []
    f = LabFuzzer(mutator=[("v1", b"A")], progress=lambda m, p: seen.append((m, p)))
    monkeypatch.setattr(f, "_probe_http", lambda url: True)
    monkeypatch.setattr(f, "_send_http", lambda h, p, v: ("HTTP/1.1 500 err", 0, 0.01))
    f._fuzz_http("127.0.0.1", 80, "http")
    assert any("baseline" in m for m, _ in seen)
    assert any("v1" in m for m, _ in seen)


# --- _send_http error mapping ----------------------------------------------


def test_send_http_classifies_real_exceptions(monkeypatch):
    f = LabFuzzer()

    def raiser(exc):
        def conn(*a, **k):
            raise exc

        return conn

    monkeypatch.setattr(f, "_probe_http", lambda url: True)
    import services.fuzzer as fz

    orig = fz.socket.create_connection

    for exc, rc in [
        (ConnectionRefusedError(), 4),
        (ConnectionResetError(), 3),
        (TimeoutError(), 2),
    ]:
        monkeypatch.setattr(fz.socket, "create_connection", raiser(exc))
        _evid, got_rc, _el = f._send_http("h", 1, b"x")
        assert got_rc == rc, exc

    monkeypatch.setattr(fz.socket, "create_connection", orig)


def test_probe_http_true_on_success(monkeypatch):
    import services.fuzzer as fz

    class Ctx:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(
        fz.urllib.request if hasattr(fz, "urllib") else fz.socket,
        "socket",
        fz.socket.socket,
        raising=False,
    )
    # simpler: patch the urlopen used inside _probe_http
    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout=None: Ctx())
    assert LabFuzzer()._probe_http("http://127.0.0.1/") is True


def test_probe_http_false_on_error(monkeypatch):
    import urllib.request

    def boom(url, timeout=None):
        raise OSError("refused")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    assert LabFuzzer()._probe_http("http://127.0.0.1/") is False


# --- minimization -----------------------------------------------------------


def test_minimize_crash_returns_pairs(tmp_path, monkeypatch):
    binp = tmp_path / "fz"
    binp.write_text("#!/bin/sh\n", encoding="utf-8")
    crash = tmp_path / "crash-abc"
    crash.write_text("A" * 200, encoding="utf-8")

    class P:
        stdout = ""
        stderr = ""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: P())
    out = LabFuzzer().minimize_crash([str(binp)], [str(crash)])
    assert len(out) == 1
    assert out[0]["input"] == "crash-abc"
    # falls back to the raw crash text (truncated) to stay faithful
    assert out[0]["minimized"].startswith("AAAA")


def test_minimize_crash_skips_missing_binary(tmp_path):
    assert LabFuzzer().minimize_crash(["/no/such/bin"], []) == []
    assert LabFuzzer().minimize_crash([], []) == []


def test_minimize_crash_swallows_failures(tmp_path, monkeypatch):
    binp = tmp_path / "fz"
    binp.write_text("#!/bin/sh\n", encoding="utf-8")
    crash = tmp_path / "crash-x"
    crash.write_bytes(b"Z")

    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="fz", timeout=1)

    monkeypatch.setattr(subprocess, "run", boom)
    # must not raise. The crash is still reported, but with reduced=False:
    # we no longer silently return the un-reduced crash under the "minimized"
    # key, which is what the old identical-branches implementation did.
    out = LabFuzzer().minimize_crash([str(binp)], [str(crash)])
    assert len(out) == 1
    assert out[0]["reduced"] is False
    assert out[0]["minimized"] == "Z"


def test_extract_minimized_falls_back_to_crash_file(tmp_path):
    crash = tmp_path / "c"
    crash.write_text("B" * 1000, encoding="utf-8")
    out = LabFuzzer._extract_minimized("", str(crash))
    assert out == "B" * 400
    out2 = LabFuzzer._extract_minimized("some libFuzzer output", str(crash))
    assert out2 == "B" * 400


def test_mutations_payloads_are_all_bytes():
    for label, payload in MUTATIONS:
        assert isinstance(label, str) and label
        assert isinstance(payload, bytes) and payload


def test_socket_module_imported():
    # guards the import used by _send_http
    assert hasattr(socket, "create_connection")
    assert Path("/tmp").exists()
