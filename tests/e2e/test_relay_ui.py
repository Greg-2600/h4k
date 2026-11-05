"""NTLM relay lab through the real UI (sandbox canned output)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_relay_run_renders_summary(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    fill(page, "relay-targets", "smb://10.10.10.42")
    click(page, "btn-relay-run")
    wait_visible(page, "relay-summary", timeout=60)
    wait_text(page, "relay-summary", "authenticated", timeout=60)
