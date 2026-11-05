"""mDNS/SSDP sweeps through the real UI (sandbox canned devices)."""

from __future__ import annotations

from typing import Any

from .helpers import click, go_to, wait_text, wait_visible


def test_mdns_sweep_persists(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    click(page, "btn-ftv-mdns")
    wait_visible(page, "ftv-device", timeout=60)
    wait_text(page, "ftv-body", "in ledger", timeout=60)


def test_ssdp_sweep_renders(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    click(page, "btn-ftv-ssdp")
    wait_visible(page, "ftv-device", timeout=60)
