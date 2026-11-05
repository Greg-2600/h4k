"""Hygiene report through the real UI (seeded engagement has reuse)."""

from __future__ import annotations

from typing import Any

from .helpers import click, go_to, wait_text, wait_visible


def test_hygiene_report_renders(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    click(page, "btn-hygiene")
    wait_visible(page, "hygiene-body", timeout=60)
    wait_text(page, "hygiene-body", "score", timeout=60)
    wait_text(page, "hygiene-body", "reuse", timeout=60)
