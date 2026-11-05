"""Engagement timeline through the real UI (seeded estate)."""

from __future__ import annotations

from typing import Any

from .helpers import click, go_to, wait_text, wait_visible


def test_timeline_renders_seed_events(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "score")
    click(page, "btn-timeline")
    wait_visible(page, "timeline-event", timeout=60)
    wait_text(page, "timeline-body", "credential", timeout=60)
