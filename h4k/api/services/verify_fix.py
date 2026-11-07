"""Verify-fix retest + flaky detector + dedup (Backlog #64).

The retest half of the SAST loop: given a baseline finding list, a fresh
rescan (`current`), and optionally older snapshots (`history`), decide per
finding whether the fix held. Exact (rule_id, file, line) matches persist;
baseline findings missing from current are fixed; current findings in
neither baseline nor history are new. A finding absent from baseline but
present in both current and an older snapshot reappeared — flaky, not
fixed, and flagged as such (flakes must shout, never silently pass).
Duplicate findings (same rule/file/line twice in one list) collapse to
one, with the dropped count stated. Findings carrying `suppressed_by`
are tallied as suppressed, never as verified.

Read-only and offline; nothing ledgers. Malformed entries are a 400,
never silent. Sandbox returns a canned verification.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("h4k.verify_fix")


def _check_finding(finding: Any, label: str, index: int) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise ValueError(f"{label}[{index}]: must be an object")
    try:
        line = int(finding.get("line", 0) or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label}[{index}]: line must be a number") from exc
    return {
        "rule_id": str(finding.get("rule_id") or "unknown"),
        "name": str(finding.get("name") or finding.get("rule_id") or "finding"),
        "severity": str(finding.get("severity") or "info").strip().lower(),
        "cwe": str(finding.get("cwe") or ""),
        "file": str(finding.get("file") or "?"),
        "line": line,
        "suppressed_by": finding.get("suppressed_by"),
    }


def _key(finding: dict[str, Any]) -> tuple[str, str, int]:
    return (finding["rule_id"], finding["file"], finding["line"])


def _dedup(
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    seen: dict[tuple[str, str, int], dict[str, Any]] = {}
    for finding in findings:
        seen.setdefault(_key(finding), finding)
    return list(seen.values()), len(findings) - len(seen)


def verify(
    baseline: list[Any],
    current: list[Any],
    history: list[Any] | None = None,
) -> dict[str, Any]:
    """Retest baseline against a rescan; flag fixes, new, and flakes."""
    if not isinstance(baseline, list):
        raise ValueError("baseline must be a list")
    if not isinstance(current, list):
        raise ValueError("current must be a list")
    if history is None:
        history = []
    if not isinstance(history, list):
        raise ValueError("history must be a list")
    base = [_check_finding(f, "baseline", i) for i, f in enumerate(baseline)]
    curr = [_check_finding(f, "current", i) for i, f in enumerate(current)]
    past: list[dict[str, Any]] = []
    for h, snap in enumerate(history):
        if not isinstance(snap, list):
            raise ValueError(f"history[{h}]: must be a list")
        past.extend(_check_finding(f, f"history[{h}]", i) for i, f in enumerate(snap))

    base, dupes = _dedup(base)
    curr, curr_dupes = _dedup(curr)
    past_keys = {_key(f) for f in past}
    base_keys = {_key(f) for f in base}
    curr_map = {_key(f): f for f in curr}

    persists: list[dict[str, Any]] = []
    fixed: list[dict[str, Any]] = []
    for finding in base:
        (persists if _key(finding) in curr_map else fixed).append(finding)
    new: list[dict[str, Any]] = []
    flaky: list[dict[str, Any]] = []
    for key, finding in curr_map.items():
        if key in base_keys:
            continue
        if key in past_keys:
            flaky.append({**finding, "flake": "reappeared after absence"})
        else:
            new.append(finding)

    suppressed = sum(1 for f in base if f.get("suppressed_by"))
    return {
        "persists": persists,
        "persists_count": len(persists),
        "fixed": fixed,
        "fixed_count": len(fixed),
        "new": new,
        "new_count": len(new),
        "flaky": flaky,
        "flaky_count": len(flaky),
        "suppressed_count": suppressed,
        "duplicates_dropped": dupes + curr_dupes,
        "baseline_count": len(base),
        "current_count": len(curr),
    }


def sandbox_result() -> dict[str, Any]:
    """Canned verification: one persists, one fixed, one flaky."""
    return {
        "persists": [
            {
                "rule_id": "sast-sql-string",
                "name": "SQL concat",
                "severity": "high",
                "cwe": "CWE-89",
                "file": "app.py",
                "line": 15,
                "suppressed_by": None,
            }
        ],
        "persists_count": 1,
        "fixed": [
            {
                "rule_id": "sast-old-xss",
                "name": "Old XSS",
                "severity": "medium",
                "cwe": "CWE-79",
                "file": "old.py",
                "line": 3,
                "suppressed_by": None,
            }
        ],
        "fixed_count": 1,
        "new": [],
        "new_count": 0,
        "flaky": [
            {
                "rule_id": "sast-race-order",
                "name": "Order flake",
                "severity": "low",
                "cwe": "CWE-362",
                "file": "app.py",
                "line": 50,
                "suppressed_by": None,
                "flake": "reappeared after absence",
            }
        ],
        "flaky_count": 1,
        "suppressed_count": 0,
        "duplicates_dropped": 0,
        "baseline_count": 2,
        "current_count": 2,
        "sandbox": True,
    }
