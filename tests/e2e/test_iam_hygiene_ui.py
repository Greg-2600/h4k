"""IAM key hygiene card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_iam_audit_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "iam-account", "lab-account")
    fill(page, "iam-host", "10.10.10.77")
    fill(
        page,
        "iam-keys",
        '[{"UserName":"a","AccessKeyId":"AKIAIOSFODNN7EXAMPLE",'
        '"Status":"Active","CreateDate":"2024-01-01"}]',
    )
    click(page, "btn-iam-audit")
    wait_visible(page, "iam-findings", timeout=60)
    wait_text(page, "iam-findings", "finding(s)", timeout=60)
    wait_text(page, "iam-findings", "in ledger", timeout=60)
