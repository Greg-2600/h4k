"""Helm chart SAST — templating + secret checks (Backlog #40).

Fully offline analysis of an operator-pasted chart bundle (files
separated by `=== path ===` headers — nothing is cloned, rendered, or
deployed). Each file is YAML-parsed for structural checks and
line-scanned for templating smells:

- privileged / allowPrivilegeEscalation / runAsUser 0 / runAsNonRoot
  false → privilege escalation (CRITICAL/HIGH, CWE-250)
- hostNetwork / hostPID / hostIPC → host access (HIGH, CWE-250)
- added SYS_ADMIN/NET_ADMIN/ALL capabilities → HIGH
- missing runAsNonRoot / readOnlyRootFilesystem / resource limits →
  hardening gaps (MEDIUM, CWE-250/CWE-400)
- `:latest` or untagged images → floating tag (MEDIUM, Checkov CKV_K8S_14)
- `{{ … }}` inside command/args → template-controlled exec (MEDIUM)
- hardcoded passwords/tokens/keys in values.yaml or Secret stringData
  (plaintext or `b64enc`-of-literal is still a committed secret) →
  CRITICAL/HIGH (CWE-798)

Findings ledger as engagement vulns on the labeled host when
`engagement_id` is given (scope-enforced). Sandbox returns canned
findings without parsing anything.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import yaml

logger = logging.getLogger("h4k.helm_sast")

_BUNDLE_RE = re.compile(r"^===\s*(.+?)\s*===\s*$")
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|pwd|secret|api[_-]?key|apikey|token)", re.IGNORECASE
)
_TEMPLATE_RE = re.compile(r"\{\{.*?\}\}")
_LATEST_RE = re.compile(r":latest\s*$", re.IGNORECASE)
_B64ENC_LITERAL_RE = re.compile(r"b64enc\s*\)?\s*$")

_WORKLOAD_KINDS = {
    "Deployment",
    "StatefulSet",
    "DaemonSet",
    "Job",
    "CronJob",
    "Pod",
    "ReplicaSet",
    "ReplicationController",
}

_DANGEROUS_CAPS = {
    "SYS_ADMIN",
    "NET_ADMIN",
    "SYS_PTRACE",
    "DAC_OVERRIDE",
    "SYS_MODULE",
    "SYS_RAWIO",
    "ALL",
}


def parse_bundle(bundle: str) -> list[dict[str, str]]:
    """Split a pasted bundle into [{path, content}] on === path === lines."""
    files: list[dict[str, str]] = []
    current: list[str] = []
    path = "chart.yaml"
    seen_header = False
    for line in (bundle or "").splitlines():
        match = _BUNDLE_RE.match(line.strip())
        if match:
            if seen_header or "\n".join(current).strip():
                files.append({"path": path, "content": "\n".join(current)})
            path = match.group(1).strip() or "chart.yaml"
            current = []
            seen_header = True
        else:
            current.append(line)
    if seen_header or "\n".join(current).strip():
        files.append({"path": path, "content": "\n".join(current)})
    return [f for f in files if f["content"].strip()]


def _finding(
    path: str,
    severity: str,
    title: str,
    evidence: str,
    cwe: str = "",
    ref: str = "",
) -> dict[str, Any]:
    return {
        "path": path,
        "severity": severity,
        "title": title,
        "evidence": evidence[:300],
        "cwe": cwe,
        "reference": ref,
    }


def _pod_spec(doc: dict[str, Any]) -> dict[str, Any]:
    kind = str(doc.get("kind") or "")
    spec = doc.get("spec") or {}
    if not isinstance(spec, dict):
        return {}
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        spec = (spec.get("jobTemplate") or {}).get("spec") or {}
        spec = (spec.get("template") or {}).get("spec") or {}
        return spec if isinstance(spec, dict) else {}
    template = spec.get("template") or {}
    pod = (template.get("spec") or {}) if isinstance(template, dict) else {}
    return pod if isinstance(pod, dict) else {}


def _audit_containers(path: str, pod: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for flag in ("hostNetwork", "hostPID", "hostIPC"):
        if pod.get(flag) is True:
            findings.append(
                _finding(
                    path,
                    "HIGH",
                    f"{flag} shares the host namespace",
                    f"pod spec {flag}: true",
                    "CWE-250",
                )
            )
    containers: list[dict[str, Any]] = []
    for key in ("containers", "initContainers", "ephemeralContainers"):
        items = pod.get(key) or []
        containers.extend([c for c in items if isinstance(c, dict)])
    for container in containers:
        cname = str(container.get("name") or "unnamed")
        ctx = container.get("securityContext") or {}
        if not isinstance(ctx, dict):
            ctx = {}
        if ctx.get("privileged") is True:
            findings.append(
                _finding(
                    path,
                    "CRITICAL",
                    f"container {cname} is privileged",
                    f"{cname}.securityContext.privileged: true",
                    "CWE-250",
                )
            )
        if ctx.get("allowPrivilegeEscalation") is True:
            findings.append(
                _finding(
                    path,
                    "HIGH",
                    f"container {cname} allows privilege escalation",
                    f"{cname}.securityContext.allowPrivilegeEscalation: true",
                    "CWE-250",
                )
            )
        if ctx.get("runAsUser") == 0 or str(ctx.get("runAsUser")) == "0":
            findings.append(
                _finding(
                    path,
                    "HIGH",
                    f"container {cname} runs as uid 0",
                    f"{cname}.securityContext.runAsUser: 0",
                    "CWE-250",
                )
            )
        if ctx.get("runAsNonRoot") is False:
            findings.append(
                _finding(
                    path,
                    "HIGH",
                    f"container {cname} opts out of runAsNonRoot",
                    f"{cname}.securityContext.runAsNonRoot: false",
                    "CWE-250",
                )
            )
        elif "runAsNonRoot" not in ctx:
            findings.append(
                _finding(
                    path,
                    "MEDIUM",
                    f"container {cname} sets no runAsNonRoot",
                    f"{cname}.securityContext has no runAsNonRoot (may run as root)",
                    "CWE-250",
                )
            )
        if ctx.get("readOnlyRootFilesystem") is False:
            findings.append(
                _finding(
                    path,
                    "MEDIUM",
                    f"container {cname} has a writable root filesystem",
                    f"{cname}.securityContext.readOnlyRootFilesystem: false",
                    "CWE-250",
                )
            )
        caps = (ctx.get("capabilities") or {}).get("add") or []
        dangerous = sorted({str(c).upper() for c in caps} & _DANGEROUS_CAPS)
        if dangerous:
            findings.append(
                _finding(
                    path,
                    "HIGH",
                    f"container {cname} adds dangerous capabilities",
                    f"{cname}.securityContext.capabilities.add: {dangerous}",
                    "CWE-250",
                )
            )
        image = str(container.get("image") or "")
        if image and (_LATEST_RE.search(image) or ":" not in image.split("/")[-1]):
            findings.append(
                _finding(
                    path,
                    "MEDIUM",
                    f"container {cname} uses a floating image tag",
                    f"{cname}.image: {image or '(empty)'}",
                    "",
                    "https://docs.bridgecrew.io/CKV_K8S_14",
                )
            )
        for field in ("command", "args"):
            blob = " ".join(str(x) for x in (container.get(field) or []))
            if _TEMPLATE_RE.search(blob):
                findings.append(
                    _finding(
                        path,
                        "MEDIUM",
                        f"container {cname} runs template-controlled {field}",
                        f"{cname}.{field} contains {{{{ … }}}} (helm-injected exec)",
                        "CWE-94",
                    )
                )
        resources = container.get("resources") or {}
        if not isinstance(resources, dict) or not resources.get("limits"):
            findings.append(
                _finding(
                    path,
                    "MEDIUM",
                    f"container {cname} sets no resource limits",
                    f"{cname}.resources.limits missing (DoS/noisy-neighbor)",
                    "CWE-400",
                )
            )
    return findings


def _audit_values(path: str, content: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    try:
        values = yaml.safe_load(content)
    except yaml.YAMLError:
        return findings
    if not isinstance(values, dict):
        return findings
    stack: list[tuple[str, Any]] = [("", values)]
    while stack:
        prefix, node = stack.pop()
        if isinstance(node, dict):
            for key, val in node.items():
                dotted = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(val, (dict, list)):
                    stack.append((dotted, val))
                elif _SECRET_KEY_RE.search(str(key)) and str(val).strip():
                    if _TEMPLATE_RE.search(str(val)):
                        continue  # wired to a template/secret store, not literal
                    findings.append(
                        _finding(
                            path,
                            "CRITICAL",
                            f"hardcoded secret at values key {dotted}",
                            f"{dotted} holds a literal secret (move to a Secret store)",
                            "CWE-798",
                        )
                    )
        elif isinstance(node, list):
            for item in node:
                stack.append((prefix, item))
    return findings


def _audit_secret_manifest(path: str, doc: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    name = str((doc.get("metadata") or {}).get("name") or "unnamed")
    string_data = doc.get("stringData") or {}
    if isinstance(string_data, dict):
        for key, val in string_data.items():
            if str(val or "").strip() and not _TEMPLATE_RE.search(str(val)):
                findings.append(
                    _finding(
                        path,
                        "HIGH",
                        f"Secret {name} embeds plaintext {key}",
                        f"stringData.{key} is a literal (use external secret mgmt)",
                        "CWE-798",
                    )
                )
    for key, val in ((doc.get("data") or {}) or {}).items():
        if (
            _SECRET_KEY_RE.search(str(key))
            and str(val or "").strip()
            and not _TEMPLATE_RE.search(str(val))
            and not _B64ENC_LITERAL_RE.search(str(val))
        ):
            findings.append(
                _finding(
                    path,
                    "MEDIUM",
                    f"Secret {name} may embed committed secret {key}",
                    f"data.{key} looks committed (b64 of a literal is still committed)",
                    "CWE-798",
                )
            )
    return findings


def scan_files(files: list[dict[str, str]]) -> dict[str, Any]:
    """Run the template + secret checklist over [{path, content}]."""
    if not files:
        raise ValueError("bundle required (paste chart files as === path === blocks)")
    findings: list[dict[str, Any]] = []
    parsed = 0
    errors: list[str] = []
    for entry in files:
        path = str(entry.get("path") or "chart.yaml")
        content = str(entry.get("content") or "")
        if not content.strip():
            continue
        if path.rstrip("/").endswith("values.yaml"):
            findings.extend(_audit_values(path, content))
        try:
            docs = [d for d in yaml.safe_load_all(content) if d]
        except yaml.YAMLError as exc:
            errors.append(f"{path}: invalid YAML ({exc})"[:200])
            continue
        if not docs:
            # values.yaml with no docs is still values-checked above; templates
            # may be plain text with {{ }} — line-scan them.
            if "{{" in content and "values" not in path:
                findings.append(
                    _finding(
                        path,
                        "MEDIUM",
                        "unrendered template block outside values",
                        "file contains {{ }} outside values.yaml — verify quoting",
                        "CWE-94",
                    )
                )
            continue
        parsed += 1
        for doc in docs:
            if not isinstance(doc, dict) or "kind" not in doc:
                continue
            kind = str(doc.get("kind") or "")
            if kind in _WORKLOAD_KINDS:
                findings.extend(_audit_containers(path, _pod_spec(doc)))
            elif kind == "Secret":
                findings.extend(_audit_secret_manifest(path, doc))
    return {
        "files": len(files),
        "parsed": parsed,
        "errors": errors,
        "findings": findings,
        "finding_count": len(findings),
        "clean": not findings,
    }


def to_ledger(
    host: str, chart: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map chart findings to engagement vuln rows for the labeled host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        title = str(finding.get("title") or "helm-sast").strip() or "helm-sast"
        rows.append(
            {
                "host": host,
                "name": f"helm {chart}: {title}"[:220],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "helm-sast",
                "reference": str(finding.get("reference") or ""),
                "cwe": str(finding.get("cwe") or ""),
                "detail": (
                    f"path={finding.get('path', '')} "
                    f"evidence={finding.get('evidence', '')}"
                ).strip(),
            }
        )
    return rows


def sandbox_result(chart: str = "lab/app") -> dict[str, Any]:
    """Canned chart audit (nothing parsed)."""
    findings = [
        {
            "path": "templates/deploy.yaml",
            "severity": "CRITICAL",
            "title": "container app is privileged (sandbox)",
            "evidence": "app.securityContext.privileged: true (sandbox)",
            "cwe": "CWE-250",
            "reference": "",
        },
        {
            "path": "values.yaml",
            "severity": "CRITICAL",
            "title": "hardcoded secret at values key db.password (sandbox)",
            "evidence": "db.password holds a literal secret (sandbox)",
            "cwe": "CWE-798",
            "reference": "",
        },
    ]
    return {
        "chart": chart or "lab/app",
        "files": 2,
        "parsed": 2,
        "errors": [],
        "findings": findings,
        "finding_count": len(findings),
        "clean": False,
        "sandbox": True,
    }
