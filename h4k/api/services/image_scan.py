"""Container image scan — trivy image → engagement vulns (Backlog #36).

An explicit, opt-in scan of one container image you own: runs
`trivy image --format json` with a fixed argv (no shell), parses the
per-result vulnerability lists into findings, and optionally ledgers
them as engagement vulns (scope-enforced — the ledger host must be in
the engagement scope). Sandbox returns a canned finding set.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess  # nosec B404 - fixed-argv trivy image scan
from typing import Any

logger = logging.getLogger("h4k.image_scan")

_REF_RE = re.compile(
    r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$"
)


def validate_image_ref(image: str) -> str:
    """Normalize an image ref; raise ValueError when it looks hostile."""
    ref = (image or "").strip()
    if not ref:
        raise ValueError("image required")
    if len(ref) > 256:
        raise ValueError("image ref too long")
    if not _REF_RE.match(ref.lower()):
        raise ValueError("bad image ref (use name[:tag], no shell, no digest flags)")
    return ref


def _trivy() -> str | None:
    return shutil.which("trivy")


def scan_image(
    image: str,
    severity: str | None = None,
    timeout: int = 600,
) -> dict[str, Any]:
    """Run `trivy image --format json` on one image ref."""
    ref = validate_image_ref(image)
    trivy = _trivy()
    if not trivy:
        return {
            "image": ref,
            "findings": [],
            "finding_count": 0,
            "success": False,
            "error": "trivy not installed",
        }
    argv = [trivy, "image", "--format", "json", "--quiet", "--no-progress"]
    if (severity or "").strip():
        argv += ["--severity", (severity or "").strip().upper()]
    argv.append(ref)
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except subprocess.TimeoutExpired:
        return {
            "image": ref,
            "findings": [],
            "finding_count": 0,
            "success": False,
            "timed_out": True,
            "error": f"trivy timed out after {timeout}s",
        }
    except Exception as exc:
        return {
            "image": ref,
            "findings": [],
            "finding_count": 0,
            "success": False,
            "error": str(exc)[:200],
        }
    try:
        doc = json.loads(proc.stdout or "{}")
    except ValueError:
        return {
            "image": ref,
            "findings": [],
            "finding_count": 0,
            "success": False,
            "rc": proc.returncode,
            "stderr": (proc.stderr or "")[-500:],
            "error": "trivy returned non-JSON output",
        }
    findings = parse_trivy_doc(doc, ref)
    return {
        "image": ref,
        "findings": findings,
        "finding_count": len(findings),
        "success": proc.returncode == 0,
        "rc": proc.returncode,
        "stderr": (proc.stderr or "")[-500:],
    }


def parse_trivy_doc(doc: dict[str, Any], image: str) -> list[dict[str, Any]]:
    """Flatten trivy json (`Results[].Vulnerabilities[]`) into findings."""
    findings: list[dict[str, Any]] = []
    for result in doc.get("Results") or []:
        target = str(result.get("Target") or image)
        for vuln in result.get("Vulnerabilities") or []:
            cve = str(vuln.get("VulnerabilityID") or "").strip()
            if not cve:
                continue
            findings.append(
                {
                    "cve": cve,
                    "pkg": str(vuln.get("PkgName") or ""),
                    "installed": str(vuln.get("InstalledVersion") or ""),
                    "fixed": str(vuln.get("FixedVersion") or ""),
                    "severity": str(vuln.get("Severity") or "UNKNOWN").upper(),
                    "title": str(vuln.get("Title") or ""),
                    "target": target,
                    "image": image,
                }
            )
    return findings


def to_ledger(
    host: str, image: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map image findings to engagement vuln rows for one ledger host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        cve = str(finding.get("cve") or "").strip()
        if not cve:
            continue
        pkg = str(finding.get("pkg") or "")
        fixed = str(finding.get("fixed") or "")
        rows.append(
            {
                "host": host,
                "name": f"{cve} in {pkg} ({image})" if pkg else f"{cve} ({image})",
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "trivy-image",
                "reference": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "cwe": "",
                "detail": (
                    f"{finding.get('title', '')} installed={finding.get('installed', '')}"
                    f" fixed={fixed or 'n/a'} target={finding.get('target', '')}"
                ).strip(),
            }
        )
    return rows


def sandbox_result(image: str) -> dict[str, Any]:
    """Canned trivy-style result (no image pulled, no network)."""
    ref = (image or "lab/app:latest").strip() or "lab/app:latest"
    findings = [
        {
            "cve": "CVE-2023-0464",
            "pkg": "openssl",
            "installed": "3.0.8",
            "fixed": "3.0.9",
            "severity": "HIGH",
            "title": "OpenSSL X.509 policy constraints DoS (sandbox)",
            "target": "usr/local/bin/app (sandbox)",
            "image": ref,
        },
        {
            "cve": "CVE-2023-2650",
            "pkg": "openssl",
            "installed": "3.0.8",
            "fixed": "3.0.9",
            "severity": "MEDIUM",
            "title": "OpenSSL object identifier processing (sandbox)",
            "target": "usr/local/bin/app (sandbox)",
            "image": ref,
        },
    ]
    return {
        "image": ref,
        "findings": findings,
        "finding_count": len(findings),
        "success": True,
        "sandbox": True,
    }
