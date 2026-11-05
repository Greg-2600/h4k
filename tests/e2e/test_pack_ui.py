"""Recon pack + loot timeline through the real UI (seeded loot)."""

from __future__ import annotations

from typing import Any

from .helpers import click, go_to, wait_text, wait_visible


def test_loot_timeline_renders_seed_loot(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "persist")
    click(page, "btn-loot-timeline")
    wait_visible(page, "loot-event", timeout=60)
    wait_text(page, "loot-body", "credential", timeout=60)


def test_pack_empty_state(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "persist")
    click(page, "btn-pack")
    wait_text(page, "pack-body", "session id", timeout=60)
