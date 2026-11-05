"""Rule CI gate — fail on high-severity SAST (Backlog #65).

The policy half of custom rules: given h4k findings, decide whether a
CI run passes. Anything at or above the threshold fails unless its
`rule_id` is explicitly ignored — and every ignore is echoed back, so
a green gate never hides *what* was waived. Unknown severities count
as `medium` (fail-closed toward visibility, stated in the result).

Malformed entries are a 400, never silently dropped: a gate that
tolerates garbage input is worse than no gate. Sandbox returns a
canned FAIL (one critical finding over a `high` threshold) without
evaluating anything.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("h4k.ci_gate")

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VALID_THRESHOLDS = ("critical", "high", "medium", "low")


def normalize_severity(value: Any) -> str:
    """Lowercased known level, else `medium` (fail-closed toward visibility)."""
    text = str(value or "").strip().lower()
    return text if text in SEVERITY_RANK else "medium"


def _check_finding(finding: Any, index: int) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise ValueError(f"findings[{index}]: must be an object")
    return {
        "rule_id": str(finding.get("rule_id") or "unknown"),
        "name": str(finding.get("name") or finding.get("rule_id") or "finding"),
        "severity": normalize_severity(finding.get("severity")),
        "cwe": str(finding.get("cwe") or ""),
        "file": str(finding.get("file") or "?"),
        "line": finding.get("line", 1),
    }


def evaluate(
    findings: list[Any],
    fail_on: str = "high",
    ignore_rule_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Gate a finding list; returns pass/fail plus the blocking set."""
    threshold = (fail_on or "high").strip().lower()
    if threshold not in VALID_THRESHOLDS:
        raise ValueError(f"fail_on must be one of {', '.join(VALID_THRESHOLDS)}")
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    ignored_ids = {str(r) for r in (ignore_rule_ids or [])}
    counts: dict[str, int] = dict.fromkeys(SEVERITY_RANK, 0)
    blocking: list[dict[str, Any]] = []
    ignored: list[dict[str, Any]] = []
    for idx, raw in enumerate(findings):
        finding = _check_finding(raw, idx)
        counts[finding["severity"]] += 1
        if finding["rule_id"] in ignored_ids:
            ignored.append({**finding, "waived": True})
        elif SEVERITY_RANK[finding["severity"]] >= SEVERITY_RANK[threshold]:
            blocking.append(finding)
    blocking.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], f["rule_id"]))
    return {
        "passed": not blocking,
        "threshold": threshold,
        "counts": counts,
        "evaluated": len(findings),
        "blocking": blocking,
        "blocking_count": len(blocking),
        "ignored": ignored,
        "ignored_count": len(ignored),
    }


def sandbox_result() -> dict[str, Any]:
    """Canned FAIL: one critical over a `high` threshold (nothing evaluated)."""
    return {
        "passed": False,
        "threshold": "high",
        "counts": {"info": 0, "low": 0, "medium": 1, "high": 0, "critical": 1},
        "evaluated": 2,
        "blocking": [
            {
                "rule_id": "sast-secret-http",
                "name": "Hardcoded credential",
                "severity": "critical",
                "cwe": "CWE-798",
                "file": "app.py",
                "line": 12,
            }
        ],
        "blocking_count": 1,
        "ignored": [],
        "ignored_count": 0,
        "sandbox": True,
    }
