"""DAST spider card through the real UI in sandbox mode."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_spider_crawl_renders_map(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "spider-target", "http://10.10.10.5")
    click(page, "btn-spider")
    wait_visible(page, "spider-map", timeout=60)
    wait_text(page, "spider-map", "page(s)", timeout=60)
    wait_text(page, "spider-status", "pages", timeout=60)
