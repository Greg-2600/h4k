"""K8s RBAC audit card through the real UI (sandbox canned + seeded scope)."""

from __future__ import annotations

from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible

ADMIN_YAML = (
    "kind: ClusterRole\nmetadata: {name: deployer}\n"
    'rules:\n- {apiGroups: ["*"], resources: ["*"], verbs: ["*"]}\n'
)


def test_rbac_audit_and_ledger(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "rbac-host", "10.10.10.77")
    fill(page, "rbac-docs", ADMIN_YAML)
    click(page, "btn-rbac-audit")
    wait_visible(page, "rbac-findings", timeout=60)
    wait_text(page, "rbac-findings", "cluster-admin", timeout=60)
    wait_text(page, "rbac-findings", "in ledger", timeout=60)
