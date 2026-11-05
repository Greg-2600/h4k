"""Rule CI gate card through the real UI (sandbox canned)."""

from __future__ import annotations

import json
from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

FINDINGS = [
    {
        "rule_id": "sast-secret-http",
        "name": "Hardcoded credential",
        "severity": "critical",
        "file": "app.py",
        "line": 4,
    },
]


def test_ci_gate_card(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "ci-paste", json.dumps(FINDINGS))
    click(page, "btn-ci-gate")
    wait_visible(page, "ci-findings", timeout=60)
    wait_text(page, "ci-findings", "blocking", timeout=60)
    wait_text(page, "ci-status", "FAIL", timeout=60)
