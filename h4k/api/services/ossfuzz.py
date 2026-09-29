# OSS-Fuzz-style auto-runner. For a repo you own that exposes an
# LLVMFuzzerTestOneInput-style harness (or a Makefile target that builds one),
# this builds it with Address/UBSan and runs libFuzzer for N seconds, then
# collects any crash artifacts as leads. Lab-only; it builds and executes code
# the operator provides.
#
# We support two paths:
#   - "make libfuzzer" + a `./parse_fuzzer` produced by the Makefile (used by
#     the vulnlab project), or
#   - an explicit `build_cmd`/`fuzz_bin` given in the request.
import logging
import os
import re
import shutil
import subprocess  # nosec B404 - builds + runs the operator's own fuzz harness
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.runner")


def _which(tool: str) -> str | None:
    return shutil.which(tool)


def _minimize(bin_path: Path, crash: Path) -> str:
    """Best-effort reduce a crash to its smallest repro via libFuzzer.

    Delegates to services.fuzzer.libfuzzer_minimize, which runs
    libFuzzer's `-merge=1` and reads back the file it actually wrote. This
    function used to return the raw crash text on both the success and the
    failure branch -- two identical branches, which is the signature of a
    reducer that never reduced anything -- so a report could claim a
    minimized repro that was byte-for-byte the original crash.
    """
    from services.fuzzer import libfuzzer_minimize

    minimized, reduced = libfuzzer_minimize(str(bin_path), crash)
    if reduced:
        return minimized
    return crash.read_text(errors="replace")[:2000]


def _env() -> dict[str, str]:
    from services import sanitizer

    env = dict(os.environ)
    env.update(sanitizer.trace_env())
    return env


def _run(cmd: list[str], cwd: Path, timeout: int) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, caller-provided
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd),
            env=_env(),
            check=False,
        )
    except FileNotFoundError:
        return -1, "", f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return -1, "", str(exc)
    return proc.returncode, proc.stdout, proc.stderr


def _parse_crashes(log: str, build_dir: Path) -> list[dict[str, Any]]:
    """Extract crash/artifact references from a libFuzzer log."""
    out: list[dict[str, Any]] = []
    for m in re.finditer(r"artifact_prefix='([^']+)'; Test unit written to (\S+)", log):
        prefix = m.group(1)
        name = m.group(2).replace(prefix, "")
        path = build_dir / m.group(2) if prefix == "./" else Path(m.group(2))
        out.append({"name": name, "path": str(path), "exists": path.exists()})
    # also grab the sanitizer error summary line if present
    sm = re.search(r"(?:ERROR:|SUMMARY:)\s*[^\n]*", log)
    if sm and not out:
        # no artifact file path, but we can report the summary
        summary = sm.group(0)[:200]
        out.append({"name": "summary", "path": "", "exists": False, "summary": summary})
    return out


class OssFuzzRunner:
    def __init__(self, progress: Callable[[str, float], None] | None = None):
        self.progress = progress or (lambda msg, pct: None)

    def run(
        self,
        repo: Path,
        build_cmd: list[str] | None = None,
        fuzz_bin: str = "parse_fuzzer",
        seconds: int = 10,
        runs: int | None = None,
        keep_dir: Path | None = None,
    ) -> dict[str, Any]:
        """Build + fuzz a C/C++ harness for `seconds`; return leads.

        `keep_dir` (optional) is a directory that is NOT cleaned up by the
        caller; crash artifacts are copied here so they can be served/downloaded
        after the run. If None, artifacts are reported by path but may be
        removed when the caller cleans its temp repo.
        """
        if not _which("clang"):
            return {"ok": False, "error": "clang not installed"}
        keep = keep_dir or Path(tempfile.mkdtemp(prefix="h4k-ossfuzz-results-"))
        keep.mkdir(parents=True, exist_ok=True)
        steps: list[str] = []

        # 1) Build (use caller's build_cmd, else `make libfuzzer` if a Makefile
        #    exists).
        if build_cmd:
            bc = build_cmd
            label = "build_cmd"
        elif (repo / "Makefile").exists():
            bc = ["make", "libfuzzer"]
            label = "make libfuzzer"
        else:
            bc = ["make", "libfuzzer"]
            label = "make libfuzzer (default)"
        self.progress(f"[runner] building: {label}", 10)
        rc, so, se = _run(bc, repo, timeout=240)
        steps.append(f"build: {label} rc={rc}")
        if rc != 0:
            return {"ok": False, "error": f"build failed: {se[:200]}", "steps": steps}

        # 2) Locate the fuzz binary.
        bin_path = repo / fuzz_bin
        if not bin_path.exists():
            # fall back to any executable with 'fuzzer' in its name
            cands = [
                p
                for p in repo.iterdir()
                if p.is_file() and ("fuzzer" in p.name.lower() or p.name == fuzz_bin)
            ]
            bin_path = cands[0] if cands else bin_path
        if not bin_path.exists():
            return {
                "ok": False,
                "error": f"fuzz binary '{fuzz_bin}' not found",
                "steps": steps,
            }
        steps.append(f"fuzz binary: {bin_path.name}")

        # 3) Seed a tiny corpus and run the harness for `seconds`.
        corpus = keep / "corpus"
        corpus.mkdir(parents=True, exist_ok=True)
        (corpus / "seed").write_bytes(b"AAAA")

        args = [str(bin_path), "-max_len=512", "-timeout=5", "-rss_limit_mb=256"]
        # libFuzzer runs forever by default; cap by time unless `runs` set.
        if runs:
            args.append(f"-runs={runs}")
        else:
            args.append(f"-max_total_time={seconds}")
        args.append(str(corpus))

        self.progress(f"[runner] fuzzing for {seconds}s...", 40)
        rc, so, se = _run(args, repo, timeout=seconds + 30)
        steps.append(f"fuzz rc={rc} (timeout/abort expected on crash)")

        log = (so or "") + "\n" + (se or "")
        crashes = _parse_crashes(log, bin_path.parent)
        self.progress("[runner] collecting crashes", 80)

        # Copy any crash artifacts into `keep` so they survive repo cleanup,
        # and minimize each with the fuzzer binary so we return the smallest repro.
        for c in crashes:
            if c.get("exists") and c.get("path"):
                try:
                    src = Path(c["path"])
                    if src.exists():
                        dest = keep / src.name
                        shutil.copy(src, dest)
                        c["path"] = str(dest)
                        c["minimized"] = _minimize(bin_path, dest)
                except (OSError, shutil.Error):
                    pass
        return {
            "ok": True,
            "built": label,
            "fuzz_bin": bin_path.name,
            "seconds": seconds,
            "crashes": crashes,
            "log_tail": log[-1500:],
            "steps": steps,
            "artifact_dir": str(keep),
        }
