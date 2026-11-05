"""TLS cert inventory through the real UI (sandbox canned hosts)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_tls_inventory_renders(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "tls-inv-targets", "10.10.10.5, 10.10.10.9")
    click(page, "btn-tls-inv")
    wait_visible(page, "tls-inv-entry", timeout=60)
    wait_text(page, "tls-inv-body", "10.10.10.5", timeout=60)
