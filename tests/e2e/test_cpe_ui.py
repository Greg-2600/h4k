"""CPE correlate through the real UI (offline curated DB)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_cpe_correlate_renders(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "cpe-service", "ssh")
    fill(page, "cpe-product", "OpenSSH")
    fill(page, "cpe-version", "7.4")
    click(page, "btn-cpe")
    wait_visible(page, "cpe-result", timeout=60)
    wait_text(page, "cpe-result", "cpe:2.3:a:openssh", timeout=60)
