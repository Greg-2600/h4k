"""Spray-guard policy through the real UI (seeded engagement)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text


def test_spray_policy_shows_held(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    fill(page, "spray-max-user", "1")
    click(page, "btn-propagate-plan")
    wait_text(page, "prop-body", "held:", timeout=60)
