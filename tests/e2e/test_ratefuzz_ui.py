"""Rate-limit probe card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_rate_probe_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "rate-url", "http://10.10.10.77/api")
    fill(page, "rate-n", "10")
    click(page, "btn-rate-start")
    wait_visible(page, "rate-output", timeout=60)
    wait_text(page, "rate-output", "requests", timeout=60)
    wait_text(page, "rate-output", "in ledger", timeout=60)
