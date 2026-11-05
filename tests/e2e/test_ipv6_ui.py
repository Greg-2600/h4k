"""IPv6 discovery through the real UI (sandbox canned hosts)."""

from __future__ import annotations

from typing import Any

from .helpers import click, go_to, wait_text, wait_visible


def test_ipv6_discovery_renders(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "discover")
    click(page, "btn-neighbors6")
    wait_visible(page, "ipv6-neighbor", timeout=60)
    wait_text(page, "ipv6-body", "fd00::5", timeout=60)
