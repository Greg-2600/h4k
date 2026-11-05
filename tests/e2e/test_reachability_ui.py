"""Reachability card through the real UI (sandbox canned)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

BUNDLE = "=== app.py ===\nimport util\nprint(util.run())\n"


def test_reachability_card(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "reach-bundle", BUNDLE)
    click(page, "btn-reach")
    wait_visible(page, "reach-findings", timeout=60)
    wait_text(page, "reach-findings", "legacy.py", timeout=60)
