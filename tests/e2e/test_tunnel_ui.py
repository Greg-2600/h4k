"""Pivot tunnel card through the real UI (sandbox canned)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_tunnel_and_proxied_scan(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    fill(page, "tun-target", "u@h")
    click(page, "btn-tun-start")
    wait_text(page, "tun-status", "1080", timeout=60)
    fill(page, "tun-scan-target", "10.10.10.5")
    click(page, "btn-tun-scan")
    wait_visible(page, "tun-summary", timeout=60)
    wait_text(page, "tun-summary", "open", timeout=60)
