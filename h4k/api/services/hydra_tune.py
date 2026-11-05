"""Hydra parallel tune + checkpoint resume (Backlog #30).

Stock passattacks run a fixed `-t 6`. This module adds named parallel
profiles (task counts + per-attempt waits, all clamped) and a per-job
working directory so hydra's own `-R` restore file survives: an
interrupted run can be resumed instead of restarted. Nothing here
changes *what* is attacked — only how fast, and that progress is kept.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

from paths import data_dir

PROFILES: dict[str, dict[str, int]] = {
    "quick": {"tasks": 4, "wait": 0},
    "standard": {"tasks": 16, "wait": 0},
    "aggressive": {"tasks": 32, "wait": 1},
}

MAX_TASKS = 64
MAX_WAIT = 30


def resolve(
    profile: str | None = None, tasks: int | None = None, wait: int | None = None
) -> dict[str, Any]:
    """Named profile with explicit overrides; everything clamped."""
    base = dict(
        PROFILES.get((profile or "standard").strip().lower(), PROFILES["standard"])
    )
    name = (profile or "standard").strip().lower()
    if name not in PROFILES:
        name = "standard"
    if tasks is not None:
        with contextlib.suppress(TypeError, ValueError):
            base["tasks"] = max(1, min(int(tasks), MAX_TASKS))
    if wait is not None:
        with contextlib.suppress(TypeError, ValueError):
            base["wait"] = max(0, min(int(wait), MAX_WAIT))
    return {"profile": name, "tasks": base["tasks"], "wait": base["wait"]}


def fragment(tune: dict[str, Any]) -> list[str]:
    """hydra argv fragment for a resolved tune ([-t N] [-W S])."""
    argv = ["-t", str(tune["tasks"])]
    if tune.get("wait"):
        argv += ["-W", str(tune["wait"])]
    return argv


def job_dir(job_id: str) -> Path:
    """Per-job working dir: wordlists, output and hydra.restore live here."""
    path = data_dir() / "hydra" / "".join(c for c in job_id if c.isalnum())[:32]
    path.mkdir(parents=True, exist_ok=True)
    return path


def restore_file(job_id: str) -> Path:
    return job_dir(job_id) / "hydra.restore"
