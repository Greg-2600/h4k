"""Fuzz sharding — N workers, merged registry (Backlog #59).

Scale-out for the signal-guided HTTP fuzzer: one coordinator splits a
deterministically generated mutation pool into disjoint per-worker
slices (worker `i` owns slice `i`, seeded `master + i`), runs one
`LabFuzzer` per slice on threads (HTTP fuzzing is I/O-bound), and
merges every finding into a single shared `CrashRegistry` guarded by
a lock — so two workers tripping the same bug report one crash, not
two, exactly like a single run would.

Partitioning makes runs reproducible: the same seed always deals the
same slices. Thread interleaving can only reorder *when* a shared
crash is first seen, never *whether*; output candidates are sorted by
crash id for stable responses. Timeouts and per-worker iteration caps
bound the whole run; a worker exception is recorded, never fatal to
its siblings.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

from services import crashes as crash_mod
from services.fuzzer import MUTATIONS, LabFuzzer, MutationEngine

logger = logging.getLogger("h4k.fuzz_shard")

MAX_WORKERS = 8
MAX_PER_WORKER = 2000


class LockedRegistry(crash_mod.CrashRegistry):
    """A CrashRegistry whose record() is safe across worker threads."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()

    def record(self, **kwargs: Any) -> tuple[Any, bool]:
        with self._lock:
            return super().record(**kwargs)


def build_slices(
    workers: int, per_worker: int, seed: int | None, dictionary: Any = None
) -> list[list[tuple[str, bytes]]]:
    """Deal disjoint mutation slices; deterministic for a fixed seed."""
    workers = max(1, min(int(workers or 1), MAX_WORKERS))
    per_worker = max(1, min(int(per_worker or 50), MAX_PER_WORKER))
    total = workers * per_worker
    engine = MutationEngine(
        seeds=[payload for _label, payload in MUTATIONS],
        dictionary=dictionary,
        seed_value=seed if seed is not None else 0x5A1D,
    )
    pool = [engine.mutate() for _ in range(total)]
    return [pool[i * per_worker : (i + 1) * per_worker] for i in range(workers)]


def run_shard(
    host: str,
    port: int,
    scheme: str = "http",
    workers: int = 2,
    iterations: int = 50,
    seed: int | None = None,
    timeout: float = 3.0,
    progress: Callable[[str, float], None] | None = None,
) -> dict[str, Any]:
    """Fuzz with N workers over disjoint slices; return the merged registry."""
    host = (host or "").strip()
    if not host:
        raise ValueError("host required")
    workers = max(1, min(int(workers or 1), MAX_WORKERS))
    per_worker = max(1, min(int(iterations or 50), MAX_PER_WORKER))
    report = progress or (lambda _msg, _pct: None)
    slices = build_slices(workers, per_worker, seed)
    registry = LockedRegistry()
    stats: list[dict[str, Any]] = [{} for _ in range(workers)]
    errors: list[str] = []

    def _work(index: int) -> None:
        try:
            fuzzer = LabFuzzer(
                progress=lambda msg, pct: report(
                    f"[shard {index}] {msg}", pct / workers + (100.0 * index / workers)
                ),
                mutator=slices[index],
                timeout=timeout,
                iterations=len(slices[index]),
                seed=(seed if seed is not None else 0x5A1D) + index,
            )
            fuzzer.registry = registry  # type: ignore[assignment]
            cands = fuzzer._fuzz_http(host, port, scheme)
            stats[index] = {
                "worker": index,
                "iterations": len(slices[index]),
                "candidates": len(cands),
                "stats": fuzzer.stats,
            }
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("shard worker %d failed: %s", index, exc)
            errors.append(f"worker {index}: {exc}"[:160])
            stats[index] = {
                "worker": index,
                "iterations": 0,
                "candidates": 0,
                "error": str(exc)[:160],
            }

    threads = [
        threading.Thread(target=_work, args=(i,), daemon=True) for i in range(workers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    candidates = sorted(
        (record.to_dict() for record in registry),
        key=lambda c: str(c.get("crash_id", "")),
    )
    return {
        "host": host,
        "port": port,
        "scheme": scheme,
        "workers": workers,
        "per_worker": per_worker,
        "iterations": workers * per_worker,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": not candidates,
        "worker_stats": stats,
        "errors": errors,
    }


def sandbox_result(host: str = "127.0.0.1") -> dict[str, Any]:
    """Canned sharded run (no threads, no network)."""
    candidates = [
        {
            "crash_id": "sandbox-1",
            "signal": "server-error",
            "vector": "overflow",
            "repro": "GET /?q=" + "A" * 64,
            "occurrences": 3,
        }
    ]
    return {
        "host": host or "127.0.0.1",
        "port": 80,
        "scheme": "http",
        "workers": 2,
        "per_worker": 4,
        "iterations": 8,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": False,
        "worker_stats": [
            {"worker": 0, "iterations": 4, "candidates": 1},
            {"worker": 1, "iterations": 4, "candidates": 0},
        ],
        "errors": [],
        "sandbox": True,
    }
