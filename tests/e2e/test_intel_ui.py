"""Intel import through the real UI (textarea JSON)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text


def test_intel_import_pastes_rows(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "intel-json", '[{"host": "9.9.9.9", "port": 22, "service": "ssh"}]')
    click(page, "btn-intel-import")
    wait_text(page, "intel-body", "1 out of scope", timeout=60)
