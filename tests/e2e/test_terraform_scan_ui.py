"""Terraform/IaC scan card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

BUNDLE = (
    "=== main.tf ===\n"
    'resource "aws_security_group" "web" {\n'
    "  ingress {\n"
    "    from_port = 22\n"
    "    to_port = 22\n"
    '    protocol = "tcp"\n'
    '    cidr_blocks = ["0.0.0.0/0"]\n'
    "  }\n"
    "}\n"
)


def test_terraform_scan_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "tf-stack", "lab/stack")
    fill(page, "tf-host", "10.10.10.77")
    fill(page, "tf-bundle", BUNDLE)
    click(page, "btn-tf-scan")
    wait_visible(page, "tf-findings", timeout=60)
    wait_text(page, "tf-findings", "finding(s)", timeout=60)
    wait_text(page, "tf-findings", "in ledger", timeout=60)
