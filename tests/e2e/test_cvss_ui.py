"""CVSS re-score through the real UI (exact v3.1 scoring)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_cvss_rescore_applies(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "cvss-host", "10.10.10.5")
    fill(page, "cvss-name", "e2e finding")
    fill(page, "cvss-vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    fill(page, "cvss-why", "heartbleed shape")
    click(page, "btn-cvss")
    wait_visible(page, "cvss-result", timeout=60)
    wait_text(page, "cvss-result", "7.5", timeout=60)
