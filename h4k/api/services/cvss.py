"""CVSS re-score with audit trail (Backlog #24).

Severity in the engagement store is a snapshot. This module lets the
operator *override* a finding's severity with a CVSS vector, a computed
or asserted score, and a written rationale — and records who did it,
when, and what changed, so the override is auditable instead of a silent
edit.

Scoring honesty: CVSS v3.1 base scores are computed exactly per the
FIRST spec (exercised against published vectors). CVSS v4.0 vectors are
validated and stored, but their score must be asserted by the operator:
the v4 macro-vector tables are not reproduced here from memory, and a
guessed score would be worse than none.
"""

from __future__ import annotations

import math
import re
from typing import Any

_V31_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_V31_AC = {"L": 0.77, "H": 0.44}
_V31_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_V31_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_V31_UI = {"N": 0.85, "R": 0.62}
_V31_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}

_V31_KEYS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

_V40_BASE_KEYS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
_V40_VALUES: dict[str, set[str]] = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "AT": {"N", "P"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "P", "A"},
    "VC": {"H", "L", "N"},
    "VI": {"H", "L", "N"},
    "VA": {"H", "L", "N"},
    "SC": {"H", "L", "N"},
    "SI": {"S", "H", "L", "N"},
    "SA": {"S", "H", "L", "N"},
}


def _roundup(value: float) -> float:
    """FIRST Roundup: smallest 1-decimal number >= value (5-dp safe)."""
    scaled = math.ceil(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000
    return (math.floor(scaled / 10000) + 1) / 10


def parse_vector(vector: str) -> dict[str, Any]:
    """Parse and validate a CVSS:3.1 or CVSS:4.0 vector string."""
    text = (vector or "").strip()
    m = re.match(r"^CVSS:3\.1/((?:[A-Z]+:[A-Za-z]+/)*[A-Z]+:[A-Za-z]+)$", text)
    if m:
        metrics: dict[str, str] = {}
        for part in m.group(1).split("/"):
            key, _, val = part.partition(":")
            metrics[key] = val
        missing = [k for k in _V31_KEYS if k not in metrics]
        if missing:
            raise ValueError(f"v3.1 vector missing: {', '.join(missing)}")
        for key in _V31_KEYS:
            table = _table_for(key, metrics.get("S"))
            if metrics[key] not in table:
                raise ValueError(f"bad v3.1 {key}:{metrics[key]}")
        return {"version": "3.1", "metrics": metrics}
    m = re.match(r"^CVSS:4\.0/((?:[A-Z]+:[A-Za-z0-9]+/)*[A-Z]+:[A-Za-z0-9]+)$", text)
    if m:
        metrics = {}
        for part in m.group(1).split("/"):
            key, _, val = part.partition(":")
            metrics[key] = val
        missing = [k for k in _V40_BASE_KEYS if k not in metrics]
        if missing:
            raise ValueError(f"v4.0 vector missing: {', '.join(missing)}")
        for key in _V40_BASE_KEYS:
            if metrics[key] not in _V40_VALUES[key]:
                raise ValueError(f"bad v4.0 {key}:{metrics[key]}")
        return {"version": "4.0", "metrics": metrics}
    raise ValueError("vector must start with CVSS:3.1/ or CVSS:4.0/")


def _table_for(key: str, scope: str | None) -> dict[str, float]:
    if key == "AV":
        return _V31_AV
    if key == "AC":
        return _V31_AC
    if key == "PR":
        return _V31_PR_C if scope == "C" else _V31_PR_U
    if key == "UI":
        return _V31_UI
    if key in ("C", "I", "A"):
        return _V31_CIA
    if key == "S":
        return {"U": 0.0, "C": 1.0}
    return {}


def score_v31(metrics: dict[str, str]) -> float:
    """Exact CVSS v3.1 base score (FIRST spec)."""
    scope_changed = metrics["S"] == "C"
    iss = 1.0 - (
        (1 - _V31_CIA[metrics["C"]])
        * (1 - _V31_CIA[metrics["I"]])
        * (1 - _V31_CIA[metrics["A"]])
    )
    pr_table = _V31_PR_C if scope_changed else _V31_PR_U
    exploit = (
        8.22
        * _V31_AV[metrics["AV"]]
        * _V31_AC[metrics["AC"]]
        * pr_table[metrics["PR"]]
        * _V31_UI[metrics["UI"]]
    )
    if not scope_changed:
        impact = 6.42 * iss
        if impact <= 0:
            return 0.0
        return _roundup(min(impact + exploit, 10.0))
    impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
    if impact <= 0:
        return 0.0
    return _roundup(min(1.08 * (impact + exploit), 10.0))


def score_vector(vector: str, asserted: float | None = None) -> dict[str, Any]:
    """Score a vector: computed for v3.1, asserted for v4.0."""
    parsed = parse_vector(vector)
    if parsed["version"] == "3.1":
        return {
            "version": "3.1",
            "metrics": parsed["metrics"],
            "score": score_v31(parsed["metrics"]),
            "computed": True,
        }
    if asserted is None:
        raise ValueError("v4.0 needs an operator-asserted score (not computed here)")
    try:
        score = float(asserted)
    except (TypeError, ValueError) as exc:
        raise ValueError("asserted score must be a number 0-10") from exc
    if not 0.0 <= score <= 10.0:
        raise ValueError("asserted score must be a number 0-10")
    return {
        "version": "4.0",
        "metrics": parsed["metrics"],
        "score": round(score, 1),
        "computed": False,
    }


def severity_for(score: float) -> str:
    """CVSS score → severity band."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"
