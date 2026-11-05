"""Sharded fuzz card through the real UI (sandbox canned)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_shard_fuzz_card(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "sh-host", "10.10.10.77")
    fill(page, "sh-port", "3138")
    fill(page, "sh-workers", "2")
    fill(page, "sh-iters", "8")
    click(page, "btn-sh-start")
    wait_visible(page, "sh-output", timeout=60)
    wait_text(page, "sh-output", "distinct crash", timeout=120)
    wait_text(page, "sh-status", "crash", timeout=60)
