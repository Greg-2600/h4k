"""S3 policy linter card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

POLICY = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":"*","Action":["s3:GetObject"],'
    '"Resource":["arn:aws:s3:::lab/*"]}]}'
)


def test_s3_lint_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "recon")
    fill(page, "s3-bucket", "lab")
    fill(page, "s3-host", "10.10.10.77")
    fill(page, "s3-policy", POLICY)
    click(page, "btn-s3-lint")
    wait_visible(page, "s3-findings", timeout=60)
    wait_text(page, "s3-findings", "PUBLIC", timeout=60)
    wait_text(page, "s3-findings", "in ledger", timeout=60)
