"""KEV card through the real UI (bundled snapshot, offline)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_kev_check_renders(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "kev-cves", "CVE-2021-44228, CVE-9999-0001")
    click(page, "btn-kev")
    wait_visible(page, "kev-result", timeout=60)
    wait_text(page, "kev-result", "KEV", timeout=60)
