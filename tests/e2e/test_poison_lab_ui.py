"""Poison lab card through the real UI (sandbox canned capture)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_poison_lab_analyze_renders_hashes(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    fill(page, "plab-iface", "lo")
    click(page, "btn-plab-run")
    wait_visible(page, "plab-hashes", timeout=60)
    wait_text(page, "plab-hashes", "analyze on lo", timeout=60)
