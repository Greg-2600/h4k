"""Docker socket guard card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_docker_guard_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "dock-host", "10.10.10.77")
    click(page, "btn-dock-guard")
    wait_visible(page, "dock-findings", timeout=60)
    wait_text(page, "dock-findings", "socket-mounted", timeout=60)
    wait_text(page, "dock-findings", "in ledger", timeout=60)
