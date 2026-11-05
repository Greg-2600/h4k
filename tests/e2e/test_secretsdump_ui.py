"""Secretsdump card through the real UI (sandbox canned hashes)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_secretsdump_renders_hashes(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    fill(page, "sd-target", "10.10.10.42")
    fill(page, "sd-user", "admin")
    fill(page, "sd-pass", "pw")
    click(page, "btn-sd-run")
    wait_visible(page, "sd-count", timeout=60)
    wait_text(page, "sd-count", "2 hash(es)", timeout=60)
