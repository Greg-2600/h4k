"""Crash bisection card through the real UI (sandbox canned)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_bisect_and_minimize(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "bisect-input", "AAATRIGGERBBB")
    fill(page, "bisect-marker", "TRIGGER")
    click(page, "btn-bisect")
    wait_visible(page, "bisect-output", timeout=60)
    wait_text(page, "bisect-output", "TRIGGER", timeout=60)
    wait_text(page, "bisect-status", "smaller", timeout=60)
