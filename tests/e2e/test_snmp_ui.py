"""SNMP sweep card through the real UI (sandbox canned hit)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_snmp_sweep_renders_hit(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "snmp-target", "10.10.10.9")
    click(page, "btn-snmp-run")
    wait_visible(page, "snmp-working", timeout=60)
    wait_text(page, "snmp-working", "1/2 accepted", timeout=60)
