"""XSS catch lab through the real UI (sandbox canned hits)."""

from __future__ import annotations

from typing import Any

from .helpers import click, go_to, wait_text, wait_visible


def test_xss_catch_lists_hits(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    click(page, "btn-xss-start")
    wait_visible(page, "xss-url", timeout=60)
    click(page, "btn-xss-hits")
    wait_visible(page, "xss-hit", timeout=60)
    wait_text(page, "xss-body", "sandbox-token", timeout=60)
