"""WebSocket fuzz card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_ws_fuzz_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "ws-url", "ws://10.10.10.77:8765/socket")
    fill(page, "ws-seed", '{"hello":1}')
    fill(page, "ws-iters", "8")
    click(page, "btn-ws-start")
    wait_visible(page, "ws-output", timeout=60)
    wait_text(page, "ws-output", "candidate(s)", timeout=120)
    wait_text(page, "ws-output", "in ledger", timeout=60)
