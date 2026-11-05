"""SOCKS-aware scan card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_socks_scan_fingerprint_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    fill(page, "tun-target", "u@h")
    click(page, "btn-tun-start")
    wait_text(page, "tun-status", "1080", timeout=60)
    fill(page, "tun-scan-target", "10.10.10.77")
    click(page, "btn-tun-scan")
    wait_visible(page, "tun-summary", timeout=60)
    # Fingerprint: service names replace raw banners; ledger count shown.
    wait_text(page, "tun-summary", "fingerprinted", timeout=60)
    wait_text(page, "tun-summary", "ledgered", timeout=60)
