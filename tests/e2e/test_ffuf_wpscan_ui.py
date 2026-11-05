"""ffuf/wpscan buttons through the real UI (sandbox refusals render)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text


def test_ffuf_and_wpscan_cards_run(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "web-target", "http://127.0.0.1:8080")
    click(page, "btn-ffuf")
    # sandbox refuses to spawn ffuf; the refusal itself must render
    wait_text(page, "web-body", "sandbox", timeout=60)
    click(page, "btn-wpscan")
    wait_text(page, "web-body", "sandbox", timeout=60)
