"""SQLMap dump card through the real UI (sandbox canned dump)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_sqlmap_dump_renders(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "sql-url", "http://10.10.10.5/vuln.php?id=1")
    click(page, "btn-sql-dump")
    wait_visible(page, "sql-dump", timeout=120)
    wait_text(page, "sql-dump", "2 table(s)", timeout=60)
