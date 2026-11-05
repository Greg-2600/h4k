"""Session fuzz card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_session_fuzz_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "web-target", "http://10.10.10.77/private")
    fill(page, "sess-marker", "Logout")
    fill(page, "sess-cookies", "session=valid")
    click(page, "btn-sess-fuzz")
    wait_visible(page, "sess-probes", timeout=60)
    wait_text(page, "sess-probes", "finding(s)", timeout=60)
    wait_text(page, "sess-probes", "in ledger", timeout=60)
