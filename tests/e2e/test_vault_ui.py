"""Loot vault through the real UI (masked by default)."""

from __future__ import annotations

from typing import Any

from .helpers import click, go_to, wait_text, wait_visible


def test_vault_masked_by_default(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "score")
    click(page, "btn-vault")
    wait_visible(page, "vault-count", timeout=60)
    wait_text(page, "vault-body", "masked", timeout=60)
