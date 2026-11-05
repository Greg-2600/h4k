"""GraphQL probe card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_graphql_probe_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "gql-url", "http://10.10.10.77/graphql")
    click(page, "btn-gql-probe")
    wait_visible(page, "gql-probes", timeout=60)
    wait_text(page, "gql-probes", "finding(s)", timeout=60)
    wait_text(page, "gql-probes", "in ledger", timeout=60)
