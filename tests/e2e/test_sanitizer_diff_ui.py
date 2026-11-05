"""Sanitizer diff card through the real UI (sandbox canned)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

ASAN = """ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1234
    #0 0xaaaa in vuln_parse vuln.c:42
SUMMARY: AddressSanitizer: heap-buffer-overflow"""


def test_sanitizer_diff_card(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "sandiff-report", ASAN)
    click(page, "btn-sandiff")
    wait_visible(page, "sandiff-findings", timeout=60)
    wait_text(page, "sandiff-findings", "heap-buffer-overflow", timeout=60)
    wait_text(page, "sandiff-findings", "ASan: yes", timeout=60)
