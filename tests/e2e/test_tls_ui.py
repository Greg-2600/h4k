"""TLS fingerprint card through the real UI (sandbox canned probe)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_tls_fingerprint_renders(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "tls-target", "10.10.10.5")
    click(page, "btn-tls-run")
    wait_visible(page, "tls-probe", timeout=60)
    wait_text(page, "tls-status", "TLS port(s)", timeout=60)
