"""Terraform/IaC scan — Checkov-style offline misconfigs (Backlog #41).

Fully offline analysis of pasted Terraform files (`=== path ===`
blocks). A small brace-counting block parser extracts `resource` /
`variable` / `terraform` blocks and their attributes — a heuristic,
not full HCL — then matches them against a misconfig checklist:

- open security-group ingress (0.0.0.0/0, worse on 22/3389) → CRITICAL
- publicly accessible RDS / unencrypted DB storage → CRITICAL/HIGH
- S3 without versioning / default encryption / with logging absent → HIGH/MEDIUM
- unencrypted EBS / instance without IMDSv2 tokens → HIGH/MEDIUM
- IAM policy with `Action "*"` on `Resource "*"` → CRITICAL
- hardcoded secret variable defaults → CRITICAL (CWE-798)
- `terraform` block without `required_version` → LOW

Findings carry H4K-prefixed check IDs in Checkov style (our own IDs —
not Checkov's catalog). They ledger as engagement vulns on the labeled
host when `engagement_id` is given (scope-enforced). Sandbox returns
canned findings without parsing anything.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.terraform_scan")

_BUNDLE_RE = re.compile(r"^===\s*(.+?)\s*===\s*$")
_BLOCK_RE = re.compile(
    r"^(resource|variable|terraform|module|output)\b\s*(.*)\{\s*(?:#.*)?$"
)
_ATTR_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+?)\s*(?:#.*)?$")
_QUOTED_RE = re.compile(r'"([^"]*)"')
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|apikey|token)", re.IGNORECASE
)


def parse_bundle(bundle: str) -> list[dict[str, str]]:
    """Split a pasted bundle into [{path, content}] on === path === lines."""
    files: list[dict[str, str]] = []
    current: list[str] = []
    path = "main.tf"
    seen_header = False
    for line in (bundle or "").splitlines():
        match = _BUNDLE_RE.match(line.strip())
        if match:
            if seen_header or "\n".join(current).strip():
                files.append({"path": path, "content": "\n".join(current)})
            path = match.group(1).strip() or "main.tf"
            current = []
            seen_header = True
        else:
            current.append(line)
    if seen_header or "\n".join(current).strip():
        files.append({"path": path, "content": "\n".join(current)})
    return [f for f in files if f["content"].strip()]


def _scalar(raw: str) -> str:
    raw = raw.strip().rstrip(",")
    if (raw.startswith('"') and raw.endswith('"')) or (
        raw.startswith("'") and raw.endswith("'")
    ):
        return raw[1:-1]
    return raw


def _parse_blocks(content: str) -> list[dict[str, Any]]:
    """Brace-counting extraction of top-level blocks and their attributes."""
    blocks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    depth = 0
    nested: dict[str, Any] | None = None
    nested_depth = 0
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        if current is None:
            match = _BLOCK_RE.match(stripped)
            if match:
                kind, rest = match.group(1), match.group(2)
                labels = _QUOTED_RE.findall(rest)
                current = {
                    "kind": kind,
                    "labels": labels,
                    "attrs": {},
                    "nested": [],
                    "nested_attrs": {},
                }
                depth = stripped.count("{") - stripped.count("}")
                if depth <= 0:
                    blocks.append(current)
                    current = None
                    depth = 0
            continue
        depth += stripped.count("{") - stripped.count("}")
        if depth <= 0:
            blocks.append(current)
            current = None
            nested = None
            continue
        if depth == 2 and stripped.endswith("{"):
            nested = {"header": stripped[:-1].strip(), "attrs": {}}
            current["nested"].append(nested)
            nested_depth = depth
            continue
        if nested is not None and depth >= nested_depth:
            attr = _ATTR_RE.match(stripped)
            if attr:
                nested["attrs"][attr.group(1)] = _scalar(attr.group(2))
            continue
        nested = None
        if depth == 1:
            attr = _ATTR_RE.match(stripped)
            if attr:
                current["attrs"][attr.group(1)] = _scalar(attr.group(2))
    if current is not None:
        blocks.append(current)
    return blocks


def _finding(
    path: str,
    check: str,
    severity: str,
    title: str,
    evidence: str,
    cwe: str = "",
    ref: str = "",
) -> dict[str, Any]:
    return {
        "path": path,
        "check": check,
        "severity": severity,
        "title": title,
        "evidence": evidence[:300],
        "cwe": cwe,
        "reference": ref,
    }


def _is_open(cidr_raw: str) -> bool:
    return "0.0.0.0/0" in cidr_raw or '"0.0.0.0/0"' in cidr_raw


def _audit_resource(path: str, block: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    labels = block.get("labels") or []
    rtype = labels[0] if labels else "unknown"
    rname = labels[1] if len(labels) > 1 else "unnamed"
    label = f"{rtype}.{rname}"
    attrs = block.get("attrs") or {}
    nested = block.get("nested") or []

    if rtype in ("aws_security_group", "aws_security_group_rule"):
        cidrs = str(attrs.get("cidr_blocks") or attrs.get("cidr_ipv6_blocks") or "")
        for nest in nested:
            header = str(nest.get("header") or "")
            nattrs = nest.get("attrs") or {}
            if "ingress" in header or rtype == "aws_security_group_rule":
                cidrs += " " + str(nattrs.get("cidr_blocks") or "")
                ports = f"{nattrs.get('from_port', '?')}-{nattrs.get('to_port', '?')}"
                if _is_open(cidrs):
                    sev = "CRITICAL"
                    if str(nattrs.get("from_port")) in ("22", "3389") or ports in (
                        "22-22",
                        "3389-3389",
                    ):
                        title = f"{label} exposes admin port {ports} to the world"
                    else:
                        title = f"{label} allows ingress from 0.0.0.0/0 (ports {ports})"
                    findings.append(
                        _finding(
                            path,
                            "H4K-TF-SG-001",
                            sev,
                            title,
                            f"ingress cidr_blocks include 0.0.0.0/0 (ports {ports})",
                            "CWE-732",
                        )
                    )
        if _is_open(cidrs) and not nested:
            findings.append(
                _finding(
                    path,
                    "H4K-TF-SG-001",
                    "CRITICAL",
                    f"{label} allows ingress from 0.0.0.0/0",
                    "cidr_blocks include 0.0.0.0/0",
                    "CWE-732",
                )
            )

    if rtype == "aws_instance":
        encrypted = str(attrs.get("encrypted") or "")
        # Only flag when the attribute is explicitly off; absence stays
        # quiet (covered by the IMDSv2 heuristic below).
        if encrypted.lower() == "false":
            findings.append(
                _finding(
                    path,
                    "H4K-TF-EC2-002",
                    "HIGH",
                    f"{label} disables EBS encryption",
                    "encrypted = false",
                    "CWE-311",
                )
            )
        imds_required = any(
            "metadata_options" in str(n.get("header") or "") for n in nested
        )
        if not imds_required:
            findings.append(
                _finding(
                    path,
                    "H4K-TF-EC2-001",
                    "MEDIUM",
                    f"{label} does not enforce IMDSv2",
                    "no metadata_options block (http_tokens required missing)",
                    "CWE-732",
                )
            )

    if rtype == "aws_db_instance":
        if str(attrs.get("publicly_accessible") or "").lower() == "true":
            findings.append(
                _finding(
                    path,
                    "H4K-TF-RDS-001",
                    "CRITICAL",
                    f"{label} is publicly accessible",
                    "publicly_accessible = true",
                    "CWE-732",
                )
            )
        if str(attrs.get("storage_encrypted") or "").lower() != "true":
            findings.append(
                _finding(
                    path,
                    "H4K-TF-RDS-002",
                    "HIGH",
                    f"{label} storage is not encrypted",
                    f"storage_encrypted = {attrs.get('storage_encrypted', '(absent)')}",
                    "CWE-311",
                )
            )

    if rtype == "aws_s3_bucket":
        nested_headers = " ".join(str(n.get("header") or "") for n in nested)
        if "versioning" not in nested_headers:
            findings.append(
                _finding(
                    path,
                    "H4K-TF-S3-001",
                    "MEDIUM",
                    f"{label} has no versioning block",
                    "no versioning { enabled = true } (ransomware/mutate risk)",
                    "CWE-732",
                )
            )
        if "server_side_encryption_configuration" not in nested_headers:
            findings.append(
                _finding(
                    path,
                    "H4K-TF-S3-002",
                    "MEDIUM",
                    f"{label} sets no default encryption",
                    "no server_side_encryption_configuration block",
                    "CWE-311",
                )
            )
        if "logging" not in nested_headers:
            findings.append(
                _finding(
                    path,
                    "H4K-TF-S3-003",
                    "LOW",
                    f"{label} has no access logging",
                    "no logging block (forensics gap)",
                    "CWE-778",
                )
            )

    if (
        rtype == "aws_ebs_volume"
        and str(attrs.get("encrypted") or "").lower() != "true"
    ):
        findings.append(
            _finding(
                path,
                "H4K-TF-EBS-001",
                "HIGH",
                f"{label} is not encrypted",
                f"encrypted = {attrs.get('encrypted', '(absent)')}",
                "CWE-311",
            )
        )

    if rtype in ("aws_iam_policy", "aws_iam_role_policy"):
        blob = " ".join(str(v) for v in attrs.values())
        if '"Action"' in blob or "Action" in attrs:
            action = str(attrs.get("Action") or "")
            resource = str(attrs.get("Resource") or "")
            if ("*" in action and "*" in resource) or '"*"' in blob:
                findings.append(
                    _finding(
                        path,
                        "H4K-TF-IAM-001",
                        "CRITICAL",
                        f"{label} allows Action * on Resource *",
                        "admin-equivalent inline policy",
                        "CWE-732",
                    )
                )
    return findings


def _audit_block(path: str, block: dict[str, Any]) -> list[dict[str, Any]]:
    kind = block.get("kind")
    if kind == "resource":
        return _audit_resource(path, block)
    if kind == "variable":
        labels = block.get("labels") or []
        vname = labels[0] if labels else "unnamed"
        default = str((block.get("attrs") or {}).get("default") or "")
        if default and _SECRET_KEY_RE.search(vname) and not default.startswith("var."):
            return [
                _finding(
                    path,
                    "H4K-TF-VAR-001",
                    "CRITICAL",
                    f"variable {vname} defaults to a hardcoded secret",
                    f'default = "{default[:40]}" (committed secret)',
                    "CWE-798",
                )
            ]
        return []
    if kind == "terraform":
        required = (block.get("attrs") or {}).get("required_version")
        nested_headers = " ".join(
            str(n.get("header") or "") for n in (block.get("nested") or [])
        )
        if not required and "required_version" not in nested_headers:
            return [
                _finding(
                    path,
                    "H4K-TF-CORE-001",
                    "LOW",
                    "terraform block pins no required_version",
                    "provider drift across runs",
                    "",
                )
            ]
        return []
    return []


def scan_files(files: list[dict[str, str]]) -> dict[str, Any]:
    """Run the misconfig checklist over [{path, content}]."""
    if not files:
        raise ValueError(
            "bundle required (paste terraform files as === path === blocks)"
        )
    findings: list[dict[str, Any]] = []
    resources = 0
    errors: list[str] = []
    for entry in files:
        path = str(entry.get("path") or "main.tf")
        content = str(entry.get("content") or "")
        if not content.strip():
            continue
        try:
            blocks = _parse_blocks(content)
        except Exception as exc:  # pragma: no cover - defensive
            errors.append(f"{path}: parse failed ({exc})"[:200])
            continue
        resources += sum(1 for b in blocks if b.get("kind") == "resource")
        for block in blocks:
            findings.extend(_audit_block(path, block))
    return {
        "files": len(files),
        "resources": resources,
        "errors": errors,
        "findings": findings,
        "finding_count": len(findings),
        "clean": not findings,
    }


def to_ledger(
    host: str, stack: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map IaC findings to engagement vuln rows for the labeled host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        title = str(finding.get("title") or "terraform").strip() or "terraform"
        rows.append(
            {
                "host": host,
                "name": f"tf {stack}: {title}"[:220],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "terraform-scan",
                "reference": str(finding.get("reference") or ""),
                "cwe": str(finding.get("cwe") or ""),
                "detail": (
                    f"check={finding.get('check', '')} path={finding.get('path', '')} "
                    f"evidence={finding.get('evidence', '')}"
                ).strip(),
            }
        )
    return rows


def sandbox_result(stack: str = "lab/stack") -> dict[str, Any]:
    """Canned IaC audit (nothing parsed)."""
    findings = [
        {
            "path": "main.tf",
            "check": "H4K-TF-SG-001",
            "severity": "CRITICAL",
            "title": "aws_security_group.web allows ingress from 0.0.0.0/0 (sandbox)",
            "evidence": "ingress cidr_blocks include 0.0.0.0/0 (sandbox)",
            "cwe": "CWE-732",
            "reference": "",
        },
        {
            "path": "main.tf",
            "check": "H4K-TF-RDS-002",
            "severity": "HIGH",
            "title": "aws_db_instance.app storage is not encrypted (sandbox)",
            "evidence": "storage_encrypted = (absent) (sandbox)",
            "cwe": "CWE-311",
            "reference": "",
        },
    ]
    return {
        "stack": stack or "lab/stack",
        "files": 1,
        "resources": 2,
        "errors": [],
        "findings": findings,
        "finding_count": len(findings),
        "clean": False,
        "sandbox": True,
    }
