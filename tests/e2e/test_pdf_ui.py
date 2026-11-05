"""Session PDF button through the real UI."""

from __future__ import annotations

from typing import Any

from .helpers import click, find, go_to


def test_session_pdf_button_present(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "score")
    assert find(page, "btn-session-pdf").is_displayed()
    click(page, "btn-session-pdf")
