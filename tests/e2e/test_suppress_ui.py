"""Suppress-finding card through the real UI (reason + expiry)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_suppress_flow(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "sup-host", "10.10.10.5")
    fill(page, "sup-name", "e2e old lead")
    fill(page, "sup-reason", "patched in lab")
    click(page, "btn-suppress")
    wait_visible(page, "sup-done", timeout=60)
    wait_text(page, "sup-done", "suppressed", timeout=60)
    click(page, "btn-sup-list")
    wait_text(page, "sup-body", "patched in lab", timeout=60)
