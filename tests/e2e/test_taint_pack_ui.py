"""Taint rules card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

BUNDLE = (
    "=== app.py ===\n"
    "import os\ndef ping():\n"
    "    host = request.args.get('h')\n"
    "    os.system('ping -c1 ' + host)\n"
)


def test_taint_scan_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "taint-host", "10.10.10.77")
    fill(page, "taint-bundle", BUNDLE)
    click(page, "btn-taint-scan")
    wait_visible(page, "taint-findings", timeout=60)
    wait_text(page, "taint-findings", "finding(s)", timeout=60)
    wait_text(page, "taint-findings", "in ledger", timeout=60)
