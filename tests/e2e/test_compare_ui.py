"""Engagement compare through the real UI (two seeded runs)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_compare_two_runs(page: Any, seeded: dict[str, Any], api: Any) -> None:
    status, payload = api.post("/api/engagement/sandbox-seed")
    assert status == 200, payload
    other = payload["engagement"]["id"]
    assert other != seeded["id"]
    go_to(page, "score")
    fill(page, "cmp-to", other)
    click(page, "btn-compare")
    wait_visible(page, "compare-summary", timeout=60)
    wait_text(page, "compare-body", "vulns", timeout=60)
