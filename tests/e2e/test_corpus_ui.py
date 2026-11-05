"""Shared corpus card through the real UI (sandbox; filesystem-backed)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_corpus_share_and_list(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "corpus-name", "lab-seed")
    fill(page, "corpus-text", "AAAA-fuzz-seed")
    click(page, "btn-corpus-add")
    wait_text(page, "corpus-status", "seed(s)", timeout=60)
    wait_visible(page, "corpus-output", timeout=60)
    wait_text(page, "corpus-output", "lab-seed", timeout=60)
