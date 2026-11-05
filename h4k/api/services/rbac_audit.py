"""K8s RBAC audit — over-permissive roles flagged (Backlog #39).

Explicit, offline analysis of operator-supplied Role/ClusterRole and
Binding YAML (parsed with `yaml.safe_load_all` — no cluster contact, no
writes). Each rule is matched against an escalation-oriented checklist:

- `*` verbs or `*` resources → cluster-admin equivalent (CRITICAL)
- `escalate` / `bind` / `impersonate` → privilege escalation (HIGH)
- secret get/list/watch → credential access (HIGH)
- pod `create` → workload creation, a node-escape path (MEDIUM)
- bindings to `system:authenticated` / `system:unauthenticated`, or to
  the `cluster-admin` role → over-broad grant (CRITICAL/HIGH)

Findings ledger as engagement vulns on the labeled host when
`engagement_id` is given (scope-enforced). Sandbox returns canned
findings without parsing anything.
"""

from __future__ import annotations

import logging
from typing import Any

import yaml

logger = logging.getLogger("h4k.rbac_audit")

_WILDCARD_VERBS = {"*"}
_ESCALATE_VERBS = {"escalate", "bind", "impersonate"}
_SECRET_VERBS = {"get", "list", "watch", "*"}
_BROAD_SUBJECTS = {"system:authenticated", "system:unauthenticated"}


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if value is None:
        return []
    return [str(value)]


def _audit_role(doc: dict[str, Any]) -> list[dict[str, Any]]:
    kind = str(doc.get("kind") or "")
    name = str((doc.get("metadata") or {}).get("name") or "unnamed")
    findings: list[dict[str, Any]] = []
    for idx, rule in enumerate(doc.get("rules") or []):
        if not isinstance(rule, dict):
            continue
        verbs = {v.lower() for v in _as_list(rule.get("verbs"))}
        resources = {r.lower() for r in _as_list(rule.get("resources"))}
        label = f"{kind}/{name} rule[{idx}]"
        if "*" in verbs and "*" in resources:
            findings.append(
                _finding(
                    label,
                    "CRITICAL",
                    "cluster-admin equivalent (* verbs on * resources)",
                    f"verbs={sorted(verbs)} resources={sorted(resources)}",
                )
            )
            continue
        if "*" in verbs:
            findings.append(
                _finding(
                    label,
                    "HIGH",
                    "wildcard verbs grant full control of listed resources",
                    f"verbs={sorted(verbs)} resources={sorted(resources)}",
                )
            )
        elif "*" in resources:
            findings.append(
                _finding(
                    label,
                    "HIGH",
                    "wildcard resources expose every API object",
                    f"verbs={sorted(verbs)} resources={sorted(resources)}",
                )
            )
        escalate = sorted(verbs & _ESCALATE_VERBS)
        if escalate:
            findings.append(
                _finding(
                    label,
                    "HIGH",
                    f"privilege-escalation verbs: {', '.join(escalate)}",
                    f"verbs={sorted(verbs)} resources={sorted(resources)}",
                )
            )
        if "secrets" in resources and (verbs & _SECRET_VERBS):
            findings.append(
                _finding(
                    label,
                    "HIGH",
                    "secret read (credential access)",
                    f"verbs={sorted(verbs)} resources={sorted(resources)}",
                )
            )
        if "pods" in resources and "create" in verbs:
            findings.append(
                _finding(
                    label,
                    "MEDIUM",
                    "pod creation (workload/node-escape path)",
                    f"verbs={sorted(verbs)} resources={sorted(resources)}",
                )
            )
    return findings


def _finding(role: str, severity: str, title: str, evidence: str) -> dict[str, Any]:
    return {
        "role": role,
        "severity": severity,
        "title": title,
        "evidence": evidence,
    }


def _audit_binding(doc: dict[str, Any]) -> list[dict[str, Any]]:
    kind = str(doc.get("kind") or "")
    name = str((doc.get("metadata") or {}).get("name") or "unnamed")
    label = f"{kind}/{name}"
    findings: list[dict[str, Any]] = []
    role_ref = doc.get("roleRef") or {}
    if str(role_ref.get("name") or "") == "cluster-admin":
        findings.append(
            _finding(
                label,
                "HIGH",
                "binding grants the cluster-admin role",
                f"roleRef={role_ref.get('kind')}/{role_ref.get('name')}",
            )
        )
    for subj in doc.get("subjects") or []:
        if not isinstance(subj, dict):
            continue
        subj_name = str(subj.get("name") or "")
        if subj_name in _BROAD_SUBJECTS:
            findings.append(
                _finding(
                    label,
                    "CRITICAL",
                    f"over-broad binding to {subj_name}",
                    f"subject kind={subj.get('kind')} name={subj_name}",
                )
            )
    return findings


def audit_documents(documents: list[str]) -> dict[str, Any]:
    """Audit pasted YAML documents; parse errors are reported, not fatal."""
    if not documents:
        raise ValueError("documents required (paste Role/ClusterRole YAML)")
    findings: list[dict[str, Any]] = []
    parsed = 0
    errors: list[str] = []
    for idx, text in enumerate(documents):
        try:
            docs = [d for d in yaml.safe_load_all(text or "") if d]
        except yaml.YAMLError as exc:
            errors.append(f"document[{idx}]: invalid YAML ({exc})"[:200])
            continue
        if not docs:
            errors.append(f"document[{idx}]: empty")
            continue
        for doc in docs:
            if not isinstance(doc, dict) or "kind" not in doc:
                errors.append(f"document[{idx}]: not a K8s manifest (no kind)")
                continue
            parsed += 1
            kind = str(doc.get("kind") or "")
            if kind in ("Role", "ClusterRole"):
                findings.extend(_audit_role(doc))
            elif kind in ("RoleBinding", "ClusterRoleBinding"):
                findings.extend(_audit_binding(doc))
            else:
                errors.append(f"document[{idx}]: kind {kind} is not RBAC (ignored)")
    return {
        "parsed": parsed,
        "errors": errors,
        "findings": findings,
        "finding_count": len(findings),
        "risky": not findings,
    }


def to_ledger(host: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map RBAC findings to engagement vuln rows for the labeled host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        role = str(finding.get("role") or "rbac").strip() or "rbac"
        rows.append(
            {
                "host": host,
                "name": f"rbac {role}",
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "rbac-audit",
                "reference": "",
                "cwe": "CWE-732",
                "detail": (
                    f"{finding.get('title', '')} evidence={finding.get('evidence', '')}"
                ).strip(),
            }
        )
    return rows


def sandbox_result() -> dict[str, Any]:
    """Canned audit (nothing parsed, no cluster contact)."""
    findings = [
        {
            "role": "ClusterRole/deployer rule[0]",
            "severity": "CRITICAL",
            "title": "cluster-admin equivalent (* verbs on * resources) (sandbox)",
            "evidence": "verbs=['*'] resources=['*'] (sandbox)",
        },
        {
            "role": "ClusterRole/reader rule[0]",
            "severity": "HIGH",
            "title": "secret read (credential access) (sandbox)",
            "evidence": "verbs=['get', 'list'] resources=['secrets'] (sandbox)",
        },
    ]
    return {
        "parsed": 2,
        "errors": [],
        "findings": findings,
        "finding_count": len(findings),
        "risky": False,
        "sandbox": True,
    }
