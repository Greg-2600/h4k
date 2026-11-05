"""AFL++ runner card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_afl_run_and_status(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "afl-target", "/lab/harness")
    click(page, "btn-afl-start")
    wait_visible(page, "afl-output", timeout=60)
    wait_text(page, "afl-output", "crashes", timeout=60)
    wait_text(page, "afl-status", "crash", timeout=60)
    click(page, "btn-afl-stop")
