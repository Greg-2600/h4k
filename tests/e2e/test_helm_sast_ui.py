"""Helm chart SAST card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

BUNDLE = (
    "=== templates/deploy.yaml ===\n"
    "kind: Deployment\nmetadata: {name: app}\n"
    "spec:\n  template:\n    spec:\n      containers:\n"
    "      - {name: app, image: x:1}\n"
)


def test_helm_scan_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "helm-chart", "lab/app")
    fill(page, "helm-host", "10.10.10.77")
    fill(page, "helm-bundle", BUNDLE)
    click(page, "btn-helm-scan")
    wait_visible(page, "helm-findings", timeout=60)
    wait_text(page, "helm-findings", "finding(s)", timeout=60)
    wait_text(page, "helm-findings", "in ledger", timeout=60)
