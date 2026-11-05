"""Kubelet audit card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def test_kubelet_audit_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "kube-host", "10.10.10.77")
    fill(page, "kube-port", "10250")
    click(page, "btn-kube-audit")
    wait_visible(page, "kube-findings", timeout=60)
    wait_text(page, "kube-findings", "anonymous-pods", timeout=60)
    wait_text(page, "kube-findings", "in ledger", timeout=60)
