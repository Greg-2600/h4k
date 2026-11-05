"""Secrets baseline card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

BUNDLE = "=== app.py ===\nKEY = 'AKIAIOSFODNN7EXAMPLE'\n"


def test_secrets_scan_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "sec-host", "10.10.10.77")
    fill(page, "sec-allow", "fixtures")
    fill(page, "sec-bundle", BUNDLE)
    click(page, "btn-sec-scan")
    wait_visible(page, "sec-findings", timeout=60)
    wait_text(page, "sec-findings", "new", timeout=60)
    wait_text(page, "sec-findings", "in ledger", timeout=60)
