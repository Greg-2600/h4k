"""Kerberos roast card through the real UI (sandbox canned hashes)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_krb_asrep_renders_hashes(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    fill(page, "krb-domain", "LAB.LOCAL")
    fill(page, "krb-users", "alice")
    click(page, "btn-krb-asrep")
    wait_visible(page, "krb-hashes", timeout=60)
    wait_text(page, "krb-hashes", "1 hash(es)", timeout=60)


def test_krb_kerberoast_renders_hashes(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "pivot")
    fill(page, "krb-domain", "LAB.LOCAL")
    fill(page, "krb-user", "svc")
    fill(page, "krb-pass", "pw")
    click(page, "btn-krb-roast")
    wait_visible(page, "krb-hashes", timeout=60)
    wait_text(page, "krb-hashes", "1 hash(es)", timeout=60)
