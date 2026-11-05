"""AFL++ persistent runner — harness + stats (Backlog #52).

Lab-only supervision of AFL++ campaigns against binaries YOU built
with `afl-cc`. Each run owns a directory under `<data_dir>/afl/`
(`in/` seeds, `out/` findings, `harness.c`, `run.json`):

- `create_run` writes a persistent-mode harness template (`harness.c`
  with an `__AFL_LOOP`, stdin-fed, calling one `target_func`) plus
  the exact `afl-clang-fast` build command — the operator compiles
  their own target, h4k never fetches code.
- `launch` supervises `afl-fuzz -i in -o out -- target args` (fixed
  argv, no shell). When `afl-fuzz` is absent the run stays `ready`
  with setup notes instead of pretending to fuzz — the same honesty
  as the trivy-missing path.
- `read_stats` parses `out/fuzzer_stats` (execs, edges, crashes,
  hangs, last crash) live on every status poll.
- `import_crashes` copies `out/crashes/id:*` payloads into the shared
  corpus (#51) with dedup accounting.

Crash findings ledger as engagement vulns on the labeled host when
`engagement_id` is given (scope-enforced, candidates labeled
unclassified). Sandbox returns a canned running run without spawning
anything.
"""

from __future__ import annotations

import json
import logging
import shutil
import signal
import subprocess  # nosec B404 - fixed-argv afl-fuzz supervision
import time
import uuid
from pathlib import Path
from typing import Any

from paths import data_dir

logger = logging.getLogger("h4k.afl_runner")

SETUP_NOTES = (
    "afl-fuzz not found. Install AFL++ (https://github.com/AFLplusplus/AFLplusplus), "
    "build your target with afl-clang-fast, then re-launch this run: "
    "afl-fuzz -i <run>/in -o <run>/out -- <target> [args]. "
    "The generated harness.c shows the persistent-mode shape."
)


def afl_dir() -> Path:
    """Persistent runs live here (created on first use)."""
    path = data_dir() / "afl"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.debug("afl dir unwritable: %s", exc)
    return path


def which_afl() -> str | None:
    return shutil.which("afl-fuzz")


def harness_c(func: str = "target_func") -> str:
    """Persistent-mode harness template for the operator's target."""
    name = "".join(
        c if (c.isalnum() or c == "_") else "_" for c in (func or "target_func")
    )
    return f"""// AFL++ persistent-mode harness template (Backlog #52).
// Build YOUR target with: afl-clang-fast -o harness harness.c target.c
// Then point an h4k AFL++ run at ./harness.
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

extern int {name}(const uint8_t *buf, size_t len);

__AFL_FUZZ_INIT();

int main(void) {{
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(1000)) {{
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        if ({name}(buf, len) != 0) {{
            fprintf(stderr, "target returned nonzero\\n");
        }}
    }}
    return 0;
}}
"""


def _run_path(run_id: str) -> Path:
    clean = "".join(c for c in run_id if c.isalnum() or c in "-_")
    if not clean:
        raise ValueError("run id required")
    return afl_dir() / clean


def create_run(
    target: str,
    args: list[str] | None = None,
    seeds: list[bytes] | None = None,
    func: str = "target_func",
) -> dict[str, Any]:
    """Create a supervised run dir with seeds + harness (no process yet)."""
    target = (target or "").strip()
    if not target:
        raise ValueError("target required (path to your afl-cc-built binary)")
    run_id = uuid.uuid4().hex[:12]
    root = _run_path(run_id)
    (root / "in").mkdir(parents=True, exist_ok=True)
    (root / "out").mkdir(parents=True, exist_ok=True)
    (root / "harness.c").write_text(harness_c(func), encoding="utf-8")
    count = 0
    for idx, seed in enumerate(seeds or [b"seed"]):
        if not seed:
            continue
        (root / "in" / f"seed-{idx:04d}").write_bytes(seed[:1_000_000])
        count += 1
    meta = {
        "id": run_id,
        "target": target,
        "args": list(args or []),
        "created": time.time(),
        "status": "ready",
        "seeds": count,
    }
    (root / "run.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return {**meta, "dir": str(root)}


def _load_meta(run_id: str) -> dict[str, Any]:
    try:
        return json.loads((_run_path(run_id) / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ValueError("unknown run") from None


def _save_meta(run_id: str, meta: dict[str, Any]) -> None:
    try:
        (_run_path(run_id) / "run.json").write_text(
            json.dumps(meta, indent=1), encoding="utf-8"
        )
    except OSError as exc:
        logger.debug("run meta unwritable: %s", exc)


def launch(
    run_id: str,
    target: str,
    args: list[str] | None = None,
    oneshot: bool = False,
) -> dict[str, Any]:
    """Start `afl-fuzz` supervised; explicit setup notes when absent."""
    meta = _load_meta(run_id)
    binary = which_afl()
    if binary is None:
        meta["status"] = "ready"
        meta["note"] = SETUP_NOTES
        _save_meta(run_id, meta)
        return {"started": False, "error": SETUP_NOTES, "run_id": run_id}
    root = _run_path(run_id)
    cmd = [binary, "-i", str(root / "in"), "-o", str(root / "out")]
    if oneshot:
        cmd += ["-V", "5"]
    cmd += ["--", target, *(args or [])]
    try:
        proc = subprocess.Popen(  # nosec B603 - fixed argv, no shell
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        return {"started": False, "error": str(exc)[:200], "run_id": run_id}
    meta.update({"status": "running", "pid": proc.pid, "started": time.time()})
    _save_meta(run_id, meta)
    return {"started": True, "run_id": run_id, "pid": proc.pid}


def read_stats(run_id: str) -> dict[str, Any]:
    """Parse out/fuzzer_stats; missing file means not started (yet)."""
    _load_meta(run_id)  # unknown runs are a 404 upstream, not empty stats
    root = _run_path(run_id)
    stats_path = root / "out" / "fuzzer_stats"
    stats: dict[str, Any] = {}
    try:
        for line in stats_path.read_text(encoding="utf-8").splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            stats[key] = int(value) if value.isdigit() else value
    except OSError:
        return {
            "running": False,
            "stats": {},
            "note": "no fuzzer_stats yet (not started?)",
        }
    crashes = (
        sorted((root / "out" / "crashes").glob("id:*"))
        if (root / "out" / "crashes").is_dir()
        else []
    )
    return {
        "running": True,
        "stats": stats,
        "execs": stats.get("execs_done", 0),
        "edges": stats.get("edges_found", 0),
        "crashes": len(crashes),
        "hangs": (
            stats.get("hangs_saved", 0)
            if isinstance(stats.get("hangs_saved"), int)
            else 0
        ),
        "last_crash": stats.get("last_crash", ""),
        "crash_files": [p.name for p in crashes[:32]],
    }


def list_crashes(run_id: str) -> list[dict[str, Any]]:
    """Crash payloads with sizes (bytes stay on disk until imported)."""
    root = _run_path(run_id)
    out: list[dict[str, Any]] = []
    crash_dir = root / "out" / "crashes"
    if not crash_dir.is_dir():
        return out
    for path in sorted(crash_dir.glob("id:*"))[:64]:
        try:
            out.append({"file": path.name, "size": path.stat().st_size})
        except OSError:
            continue
    return out


def stop_run(run_id: str, jobs: dict[str, Any]) -> dict[str, Any]:
    """Terminate the supervised process (if any) and mark the run stopped."""
    meta = _load_meta(run_id)
    job = jobs.get(run_id) or {}
    pid = job.get("pid", meta.get("pid"))
    try:
        if pid:
            import os

            os.kill(int(pid), signal.SIGTERM)
    except (OSError, ValueError):
        pass
    meta["status"] = "stopped"
    _save_meta(run_id, meta)
    job["status"] = "stopped"
    return {"stopped": True, "run_id": run_id}


def import_crashes(run_id: str, source: str = "") -> dict[str, Any]:
    """Copy crash payloads into the shared corpus (#51) with dedup counts."""
    try:
        from services.corpus import add_entry
    except ImportError as exc:
        raise ValueError(
            "shared corpus unavailable (lands with the corpus-sync change)"
        ) from exc

    root = _run_path(run_id)
    crash_dir = root / "out" / "crashes"
    added = deduped = 0
    errors: list[str] = []
    if not crash_dir.is_dir():
        return {"added": 0, "deduped": 0, "errors": ["no crashes dir yet"]}
    for path in sorted(crash_dir.glob("id:*")):
        try:
            out = add_entry(
                path.read_bytes(),
                name=path.name,
                source=source or f"afl:{run_id}",
                tags=["afl", "crash"],
            )
            if out.get("deduped"):
                deduped += 1
            else:
                added += 1
        except (OSError, ValueError) as exc:
            errors.append(f"{path.name}: {exc}"[:160])
    return {"added": added, "deduped": deduped, "errors": errors}


def to_ledger(
    host: str, run_id: str, crashes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map crash payloads to engagement vuln rows (labeled unclassified)."""
    rows: list[dict[str, Any]] = []
    for crash in crashes:
        rows.append(
            {
                "host": host,
                "name": f"afl-run {run_id}: crash {crash.get('file')} (unclassified)"[
                    :220
                ],
                "severity": "HIGH",
                "module": "afl-run",
                "reference": "",
                "cwe": "CWE-119",
                "detail": f"size={crash.get('size', 0)}B — triage before claiming impact".strip()[
                    :400
                ],
            }
        )
    return rows


def sandbox_run(target: str = "/lab/harness") -> dict[str, Any]:
    """Canned running run (no process spawned)."""
    crashes = [{"file": "id:000000,sig:11,src:000000", "size": 128}]
    run_id = "sandbox01abcd"
    return {
        "run_id": run_id,
        "target": target or "/lab/harness",
        "status": "running",
        "seeds": 2,
        "execs": 1048576,
        "edges": 1337,
        "crashes": crashes,
        "crash_count": len(crashes),
        "hangs": 0,
        "last_crash": "2 days ago (sandbox)",
        "clean": False,
        "sandbox": True,
    }
