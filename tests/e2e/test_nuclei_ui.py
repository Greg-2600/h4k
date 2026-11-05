"""Nuclei scan through the real UI in sandbox mode (offline bundle)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_nuclei_scan_renders_findings(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "web-target", "http://10.10.10.5")
    click(page, "btn-nuclei")
    wait_visible(page, "nuclei-findings", timeout=60)
    wait_text(page, "nuclei-findings", "1 finding(s)", timeout=60)
    wait_text(page, "nuclei-status", "1 finding(s)", timeout=60)
