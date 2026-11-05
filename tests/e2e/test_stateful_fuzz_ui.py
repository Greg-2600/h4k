"""Stateful fuzz card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

FLOW = '[{"method":"POST","url":"http://10.10.10.77/items","fields":["body:name"]}]'


def test_stateful_fuzz_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "st-login", "http://10.10.10.77/login")
    fill(page, "st-creds", '{"user":"u","pass":"p"}')
    fill(page, "st-flow", FLOW)
    click(page, "btn-st-start")
    wait_visible(page, "st-output", timeout=60)
    wait_text(page, "st-output", "candidate(s)", timeout=60)
    wait_text(page, "st-output", "in ledger", timeout=60)
