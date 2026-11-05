"""Crash bisection — input halve to minimal trigger (Backlog #54).

Generic delta-debugging (Zeller ddmin) over crashing inputs, distinct
from the libFuzzer `-minimize_crash` wrapper which needs a local
instrumented binary. Two modes, both bounded and explicit:

- `marker`: fully offline — halve the pasted input to the smallest
  substring that still contains the operator's `marker` (e.g. the
  `TRIGGER` token, a stack-trace line). Nothing is requested.
- `http`: replay shrunken candidates at the operator's OWN `url` and
  keep the smallest input that still trips the signal (HTTP status at
  or above `status_ge`, or a response `marker`). Only that URL is ever
  requested, max 64 rounds, per-request timeout.

Every kept step is recorded in a trace (round, size, kept/dropped) so
the halving is auditable instead of magic. Sandbox returns a canned
bisection without touching anything.
"""

from __future__ import annotations

import base64
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.bisect")

MAX_INPUT_BYTES = 1_000_000
MAX_ROUNDS = 64


def ddmin(
    data: bytes,
    interesting: Callable[[bytes], bool],
    max_rounds: int = MAX_ROUNDS,
) -> dict[str, Any]:
    """Halve `data` to a 1-minimal interesting input (n=2, double on stall)."""
    if not data:
        raise ValueError("input required (nothing to halve)")
    if not interesting(data):
        raise ValueError("original input is not interesting — check the marker/signal")
    current = data
    granularity = 2
    rounds = 0
    trace: list[dict[str, Any]] = []
    while len(current) >= 2 and rounds < max(1, min(int(max_rounds or 64), 256)):
        rounds += 1
        chunk = max(1, len(current) // granularity)
        reduced = False
        for start in range(0, len(current), chunk):
            candidate = current[:start] + current[start + chunk :]
            if not candidate:
                continue
            try:
                hit = interesting(candidate)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("predicate failed: %s", exc)
                continue
            kept = bool(hit)
            trace.append({"round": rounds, "size": len(candidate), "kept": kept})
            if kept:
                current = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if not reduced:
            if granularity >= len(current):
                break
            granularity = min(len(current), granularity * 2)
    return {
        "minimal": current,
        "original_size": len(data),
        "minimal_size": len(current),
        "rounds": rounds,
        "trace": trace[-32:],
    }


def _send(url: str, method: str, data: bytes, timeout: float) -> dict[str, Any]:
    started = time.time()
    try:
        req = urllib.request.Request(
            url,
            data=data if method != "GET" else None,
            headers={
                "User-Agent": "h4k-audit",
                "Content-Type": "application/octet-stream",
            },
            method=method,
        )
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as resp:  # nosec B310 - operator-supplied lab target
            body = resp.read(8192).decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "body": body,
                "elapsed": round(time.time() - started, 2),
            }
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(8192).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "status": exc.code,
            "body": body,
            "elapsed": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "status": None,
            "body": "",
            "elapsed": round(time.time() - started, 2),
            "error": str(exc)[:160],
        }


def bisect_input(
    data: bytes,
    url: str = "",
    method: str = "POST",
    marker: str = "",
    status_ge: int = 500,
    max_rounds: int = MAX_ROUNDS,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Halve to the minimal trigger, offline (marker) or against a URL."""
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds {MAX_INPUT_BYTES} bytes")
    method = (method or "POST").upper()
    if method not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
        raise ValueError("unsupported method")
    if url:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            raise ValueError("url must be an http(s) URL you own")
        threshold = int(status_ge or 500)
        mark = marker or ""

        def _interesting(candidate: bytes) -> bool:
            res = _send(url, method, candidate, timeout)
            if res.get("error"):
                raise ValueError(f"target unreachable: {res['error']}")
            if mark and mark in (res.get("body") or ""):
                return True
            try:
                return (res.get("status") or 0) >= threshold
            except TypeError:
                return False

        mode = "http"
    else:
        mark = (marker or "").strip()
        if not mark:
            raise ValueError("marker required in offline mode (or give a url)")
        mark_b = mark.encode()
        mode = "marker"

        def _interesting(candidate: bytes) -> bool:
            return mark_b in candidate

    out = ddmin(data, _interesting, max_rounds=max_rounds)
    minimal = out["minimal"]
    try:
        text = minimal.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    reduction = (
        round(100.0 * (1 - out["minimal_size"] / out["original_size"]), 1)
        if out["original_size"]
        else 0.0
    )
    return {
        "mode": mode,
        "minimal_b64": base64.b64encode(minimal).decode(),
        "minimal_text": text[:2000],
        "original_size": out["original_size"],
        "minimal_size": out["minimal_size"],
        "reduction_pct": reduction,
        "rounds": out["rounds"],
        "trace": out["trace"],
        "still_crashes": True,
    }


def sandbox_result() -> dict[str, Any]:
    """Canned bisection (no predicate evaluated)."""
    minimal = b"TRIGGER"
    return {
        "mode": "marker",
        "minimal_b64": base64.b64encode(minimal).decode(),
        "minimal_text": "TRIGGER",
        "original_size": 64,
        "minimal_size": len(minimal),
        "reduction_pct": 89.1,
        "rounds": 6,
        "trace": [
            {"round": 1, "size": 32, "kept": True},
            {"round": 6, "size": 7, "kept": True},
        ],
        "still_crashes": True,
        "sandbox": True,
    }
