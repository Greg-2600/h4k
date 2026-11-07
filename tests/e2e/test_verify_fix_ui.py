"""Verify-fix card through the real UI (sandbox canned)."""

from __future__ import annotations

import json
from typing import Any

from .helpers import click, fill, go_to, wait_text

BASE = [
    {
        "rule_id": "sast-sql-string",
        "name": "SQL concat",
        "severity": "high",
        "file": "app.py",
        "line": 15,
    },
]
CUR = [
    {
        "rule_id": "sast-sql-string",
        "name": "SQL concat",
        "severity": "high",
        "file": "app.py",
        "line": 15,
    },
]


def test_verify_card(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "verify-base", json.dumps(BASE))
    fill(page, "verify-cur", json.dumps(CUR))
    click(page, "btn-verify")
    wait_text(page, "verify-findings", "OPEN", timeout=60)
    wait_text(page, "verify-status", "still present", timeout=60)
