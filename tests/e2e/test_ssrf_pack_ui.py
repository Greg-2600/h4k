"""SSRF metadata pack card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_ssrf_probe_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "web-target", "http://10.10.10.77/fetch")
    fill(page, "ssrf-param", "url")
    click(page, "btn-ssrf-probe")
    wait_visible(page, "ssrf-probes", timeout=60)
    wait_text(page, "ssrf-probes", "VULNERABLE", timeout=60)
    wait_text(page, "ssrf-probes", "in ledger", timeout=60)
