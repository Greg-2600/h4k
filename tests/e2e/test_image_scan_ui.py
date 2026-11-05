"""Container image scan card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_image_scan_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "img-ref", "lab/app:latest")
    fill(page, "img-host", "10.10.10.77")
    click(page, "btn-img-scan")
    wait_visible(page, "img-findings", timeout=60)
    wait_text(page, "img-findings", "CVE-2023-0464", timeout=60)
    wait_text(page, "img-findings", "in ledger", timeout=60)
