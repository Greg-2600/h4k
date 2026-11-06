"""Inline-suppress card through the real UI (sandbox canned)."""

from __future__ import annotations

import json
from typing import Any

from .helpers import click, fill, go_to, wait_text

BUNDLE = """=== app.py ===
import os
os.system(x)  # line 3
"""

FINDINGS = [
    {
        "rule_id": "sast-exec-shell",
        "name": "Shell injection",
        "severity": "high",
        "file": "app.py",
        "line": 3,
    },
]


def test_suppress_card(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "nosast-bundle", BUNDLE)
    fill(page, "nosast-paste", json.dumps(FINDINGS))
    click(page, "btn-nosast")
    wait_text(page, "nosast-findings", "directive", timeout=60)
    wait_text(page, "nosast-status", "WAIVED", timeout=60)
