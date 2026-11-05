"""NSE suggest-and-run through the real UI (sandbox mode)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_nse_suggest_then_run(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "nse-target", "10.10.10.5")
    fill(page, "nse-service", "ssh")
    click(page, "btn-nse-suggest")
    wait_visible(page, "nse-suggestion", timeout=60)
    wait_text(page, "nse-body", "ssh-brute", timeout=60)
    click(page, "btn-nse-run")
    # sandbox refuses to spawn nmap; the refusal itself must render
    wait_text(page, "nse-body", "sandbox", timeout=120)
