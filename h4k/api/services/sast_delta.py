"""Delta SAST — diff-only findings per PR (Backlog #66).

The CI-gate companion: given a baseline finding list (main) and a current
list (the PR), report only what the PR introduces. Exact matches on
(rule_id, file, line) are unchanged; a finding with the same rule in the
same file within `move_tolerance` lines is "moved" (code shifted, not a
new vuln) — the tolerance and every match are stated in the result, so a
quiet diff never hides *why* something stayed quiet. Anything else in
current is new; anything left in baseline is fixed.

Malformed entries are a 400, never silently dropped: a diff that
tolerates garbage input is worse than no diff. Sandbox returns a canned
diff (one new high, one moved, one fixed) without evaluating anything.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("h4k.sast_delta")

DEFAULT_TOLERANCE = 3


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
    }


def _key(finding: dict[str, Any]) -> tuple[str, str, int]:
    return (finding["rule_id"], finding["file"], finding["line"])


def diff_findings(
    baseline: list[Any],
    current: list[Any],
    move_tolerance: int = DEFAULT_TOLERANCE,
) -> dict[str, Any]:
    """Diff two finding lists; returns new/fixed/moved plus counts."""
    if not isinstance(baseline, list):
        raise ValueError("baseline must be a list")
    if not isinstance(current, list):
        raise ValueError("current must be a list")
    try:
        tolerance = int(move_tolerance)
    except (TypeError, ValueError) as exc:
        raise ValueError("move_tolerance must be a number") from exc
    if tolerance < 0:
        raise ValueError("move_tolerance must be >= 0")
    base = [_check_finding(f, "baseline", i) for i, f in enumerate(baseline)]
    curr = [_check_finding(f, "current", i) for i, f in enumerate(current)]

    unmatched: dict[tuple[str, str, int], dict[str, Any]] = {}
    for finding in base:
        unmatched.setdefault(_key(finding), finding)
    new: list[dict[str, Any]] = []
    moved: list[dict[str, Any]] = []
    unchanged_count = 0
    for finding in curr:
        if _key(finding) in unmatched:
            del unmatched[_key(finding)]
            unchanged_count += 1
            continue
        mate_key = next(
            (
                key
                for key in unmatched
                if key[0] == finding["rule_id"]
                and key[1] == finding["file"]
                and abs(key[2] - finding["line"]) <= tolerance
            ),
            None,
        )
        if mate_key is not None:
            mate = unmatched.pop(mate_key)
            moved.append({**finding, "was_line": mate["line"]})
        else:
            new.append(finding)
    fixed = list(unmatched.values())
    return {
        "new": new,
        "new_count": len(new),
        "fixed": fixed,
        "fixed_count": len(fixed),
        "moved": moved,
        "moved_count": len(moved),
        "unchanged_count": unchanged_count,
        "baseline_count": len(base),
        "current_count": len(curr),
        "move_tolerance": tolerance,
    }


def sandbox_result() -> dict[str, Any]:
    """Canned diff: one new high, one moved, one fixed (nothing evaluated)."""
    return {
        "new": [
            {
                "rule_id": "sast-exec-shell",
                "name": "Shell injection",
                "severity": "high",
                "cwe": "CWE-78",
                "file": "app.py",
                "line": 42,
            }
        ],
        "new_count": 1,
        "fixed": [
            {
                "rule_id": "sast-hardcoded-key",
                "name": "Hardcoded key",
                "severity": "medium",
                "cwe": "CWE-798",
                "file": "old.py",
                "line": 7,
            }
        ],
        "fixed_count": 1,
        "moved": [
            {
                "rule_id": "sast-sql-string",
                "name": "SQL string concat",
                "severity": "high",
                "cwe": "CWE-89",
                "file": "app.py",
                "line": 15,
                "was_line": 13,
            }
        ],
        "moved_count": 1,
        "unchanged_count": 1,
        "baseline_count": 3,
        "current_count": 3,
        "move_tolerance": DEFAULT_TOLERANCE,
        "sandbox": True,
    }
