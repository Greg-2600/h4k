"""Privesc checklist through the real UI (sandbox canned list)."""

from __future__ import annotations

from typing import Any

from .helpers import click, go_to, wait_text, wait_visible


def test_privesc_checklist_renders(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    click(page, "btn-privesc-suggest")
    wait_visible(page, "privesc-check", timeout=60)
    wait_text(page, "privesc-suggest-body", "SUID binaries", timeout=60)
