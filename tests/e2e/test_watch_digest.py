"""Scheduled rescan + digest through the real UI (sandbox mode)."""

from __future__ import annotations

from typing import Any

from .helpers import click, go_to, wait_text, wait_visible


def test_rescan_and_digest(page: Any, seeded: dict[str, Any], api: Any) -> None:
    go_to(page, "score")
    click(page, "watch-rescan")
    wait_text(page, "watch-status", "snapshot", timeout=120)
    status, payload = api.get(f"/api/engagement/{seeded['id']}/watch/digest?fmt=md")
    assert status == 200, payload
    assert payload["content"].startswith("# Lab Watch digest")
    wait_visible(page, "watch-digest", timeout=60)
