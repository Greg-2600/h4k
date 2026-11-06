"""Delta SAST card through the real UI (sandbox canned)."""

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
        "line": 13,
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
    {
        "rule_id": "sast-exec-shell",
        "name": "Shell injection",
        "severity": "high",
        "file": "app.py",
        "line": 42,
    },
]


def test_delta_card(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "delta-base", json.dumps(BASE))
    fill(page, "delta-cur", json.dumps(CUR))
    click(page, "btn-sast-delta")
    wait_text(page, "delta-findings", "new", timeout=60)
    wait_text(page, "delta-status", "DIRTY", timeout=60)
