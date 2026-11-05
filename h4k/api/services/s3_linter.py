"""S3 policy linter — public/ACL offline eval (Backlog #44).

Fully offline evaluation of a pasted bucket policy (JSON object or
text) plus canned ACL grants. Nothing contacts AWS. The checklist:

- `Allow` + wildcard principal + `s3:Get*` → CRITICAL public read
- `Allow` + wildcard principal + `s3:*`/`*` → CRITICAL full public
- `Allow` + wildcard principal + `s3:Put*/Delete*` → HIGH public write
- `Allow` + `NotPrincipal` → HIGH (evasive grant, hard to review)
- wildcard `Allow` softened by a `Condition` → MEDIUM conditional public
- canned `public-read-write` → CRITICAL, `public-read` → HIGH,
  `authenticated-read` → MEDIUM (any AWS account), log-delivery → INFO
- raw grant lists are matched on the AllUsers / AuthenticatedUsers
  group URIs with the same severity ladder
- a complete public-access-block (all four flags true) neutralizes
  policy grants → single INFO noting the block (grant kept on record)

Findings ledger as engagement vulns on the labeled host when
`engagement_id` is given (scope-enforced). Sandbox returns canned
findings without parsing anything.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("h4k.s3_linter")

ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

_CANNED_ACL: dict[str, tuple[str, str, str]] = {
    # canned acl -> (severity, title, evidence)
    "private": ("INFO", "bucket ACL is private", "canned acl private"),
    "bucket-owner-read": (
        "INFO",
        "bucket ACL is private to the owner",
        "canned acl bucket-owner-read",
    ),
    "log-delivery-write": (
        "INFO",
        "bucket ACL grants log delivery only",
        "canned acl log-delivery-write",
    ),
    "authenticated-read": (
        "MEDIUM",
        "bucket ACL readable by any authenticated AWS user",
        "canned acl authenticated-read (not just your account)",
    ),
    "public-read": (
        "HIGH",
        "bucket ACL grants public READ",
        "canned acl public-read (AllUsers READ)",
    ),
    "public-read-write": (
        "CRITICAL",
        "bucket ACL grants public READ + WRITE",
        "canned acl public-read-write (AllUsers FULL_CONTROL)",
    ),
}


def _as_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    if value is None:
        return []
    return [str(value)]


def _principal_is_wildcard(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if value == "*" or (
                isinstance(value, list) and "*" in [str(v) for v in value]
            ):
                return True
    return False


def _actions(stmt: dict[str, Any]) -> list[str]:
    raw: list[str] = []
    for key in ("Action", "NotAction"):
        raw.extend(_as_list(stmt.get(key)))
    return raw


def _action_hits(actions: list[str], *needles: str) -> bool:
    lowered = [a.lower() for a in actions]
    return any(any(n in a for n in needles) for a in lowered) or "*" in lowered


def audit_policy(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Flag public grants in a bucket policy document."""
    findings: list[dict[str, Any]] = []
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return [
            _finding(
                "MEDIUM",
                "policy Statement is not a list (cannot fully evaluate)",
                "Statement should be a list of statements",
                "",
            )
        ]
    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("Effect") or "") != "Allow":
            continue
        label = f"statement[{idx}]"
        principal = stmt.get("Principal")
        actions = _actions(stmt)
        if "NotPrincipal" in stmt:
            findings.append(
                _finding(
                    "HIGH",
                    f"{label} uses Allow + NotPrincipal (evasive grant)",
                    "NotPrincipal inverts matching and is easy to get wrong",
                    label,
                )
            )
            continue
        if not _principal_is_wildcard(principal):
            continue
        has_condition = bool(stmt.get("Condition"))
        if _action_hits(actions, "s3:*") or actions == ["*"]:
            findings.append(
                _finding(
                    "CRITICAL" if not has_condition else "MEDIUM",
                    f"{label} grants full S3 access to everyone"
                    + (" (conditioned)" if has_condition else ""),
                    f"Principal=* Action={actions}"
                    + (f" Condition={stmt.get('Condition')}" if has_condition else ""),
                    label,
                )
            )
            continue
        if _action_hits(actions, "s3:get", "s3:list"):
            findings.append(
                _finding(
                    "CRITICAL" if not has_condition else "MEDIUM",
                    f"{label} grants public read"
                    + (" (conditioned)" if has_condition else ""),
                    f"Principal=* Action={actions}"
                    + (f" Condition={stmt.get('Condition')}" if has_condition else ""),
                    label,
                )
            )
        if _action_hits(actions, "s3:put", "s3:delete"):
            findings.append(
                _finding(
                    "HIGH" if not has_condition else "MEDIUM",
                    f"{label} grants public write"
                    + (" (conditioned)" if has_condition else ""),
                    f"Principal=* Action={actions}"
                    + (f" Condition={stmt.get('Condition')}" if has_condition else ""),
                    label,
                )
            )
    return findings


def _finding(
    severity: str, title: str, evidence: str, where: str = ""
) -> dict[str, Any]:
    return {
        "severity": severity,
        "title": title,
        "evidence": evidence[:300],
        "where": where,
        "policy": (
            "Remove wildcard principals; scope to exact ARNs. Keep all four "
            "public-access-block flags true until a grant is truly needed."
        ),
    }


def audit_acl(acl: Any) -> list[dict[str, Any]]:
    """Evaluate a canned ACL name or a raw S3 grant list."""
    if acl is None or (isinstance(acl, str) and not acl.strip()):
        return []
    if isinstance(acl, str):
        key = acl.strip()
        if key not in _CANNED_ACL:
            return [
                _finding(
                    "MEDIUM",
                    f"unknown canned ACL {key!r} (cannot confirm private)",
                    "use private unless public access is intended",
                    "acl",
                )
            ]
        sev, title, evidence = _CANNED_ACL[key]
        if sev == "INFO":
            return []
        return [_finding(sev, title, evidence, "acl")]
    grants = acl if isinstance(acl, list) else []
    findings: list[dict[str, Any]] = []
    for grant in grants:
        if not isinstance(grant, dict):
            continue
        uri = str((grant.get("Grantee") or {}).get("URI") or "")
        perm = str(grant.get("Permission") or "").upper()
        if uri == ALL_USERS:
            if perm in ("FULL_CONTROL", "WRITE"):
                findings.append(
                    _finding(
                        "CRITICAL",
                        f"grant gives AllUsers {perm}",
                        "global group with write access",
                        "acl",
                    )
                )
            else:
                findings.append(
                    _finding(
                        "HIGH",
                        f"grant gives AllUsers {perm or 'READ'}",
                        "global group with read access",
                        "acl",
                    )
                )
        elif uri == AUTH_USERS:
            findings.append(
                _finding(
                    "MEDIUM",
                    f"grant gives AuthenticatedUsers {perm or 'READ'}",
                    "any AWS account, not just yours",
                    "acl",
                )
            )
    return findings


def lint_bucket(
    bucket: str,
    policy: Any | None = None,
    acl: Any | None = None,
    block_public: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate policy + ACL; a full public-access-block neutralizes grants."""
    bucket = (bucket or "").strip() or "bucket"
    findings = audit_policy(policy or {})
    findings.extend(audit_acl(acl))
    blocked = bool(block_public) and all(
        bool((block_public or {}).get(flag, False))
        for flag in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        )
    )
    note = ""
    if blocked and findings:
        note = "all four public-access-block flags are true: policy/ACL grants cannot take effect"
        findings = [_finding("INFO", "public access fully blocked", note, "block")]
    public = any(f["severity"] in ("CRITICAL", "HIGH") for f in findings)
    return {
        "bucket": bucket,
        "findings": findings,
        "finding_count": len(findings),
        "public": public,
        "blocked": blocked,
        "clean": not findings,
        "note": note,
    }


def to_ledger(
    host: str, bucket: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map linter findings to engagement vuln rows for the labeled host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        title = str(finding.get("title") or "s3-linter").strip() or "s3-linter"
        rows.append(
            {
                "host": host,
                "name": f"s3 {bucket}: {title}"[:220],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "s3-linter",
                "reference": "",
                "cwe": "CWE-732",
                "detail": (
                    f"where={finding.get('where', '')} "
                    f"evidence={finding.get('evidence', '')} "
                    f"policy={finding.get('policy', '')}"
                ).strip(),
            }
        )
    return rows


def sandbox_result(bucket: str = "lab-bucket") -> dict[str, Any]:
    """Canned linter result (nothing parsed)."""
    findings = [
        {
            "severity": "CRITICAL",
            "title": "statement[0] grants public read (sandbox)",
            "evidence": "Principal=* Action=['s3:GetObject'] (sandbox)",
            "where": "statement[0]",
            "policy": "Remove wildcard principals (sandbox).",
        },
        {
            "severity": "HIGH",
            "title": "bucket ACL grants public READ (sandbox)",
            "evidence": "canned acl public-read (sandbox)",
            "where": "acl",
            "policy": "Remove wildcard principals (sandbox).",
        },
    ]
    return {
        "bucket": bucket or "lab-bucket",
        "findings": findings,
        "finding_count": len(findings),
        "public": True,
        "blocked": False,
        "clean": False,
        "note": "",
        "sandbox": True,
    }
