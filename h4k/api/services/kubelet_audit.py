"""Kubelet unauth audit — read-only checks (Backlog #37).

An explicit, opt-in audit of one kubelet you own (default
127.0.0.1:10250). Every probe is a plain HTTPS GET — no exec, no logs,
no writes — using only the stdlib, with an unverified TLS context
because lab kubelets serve self-signed certs.

Findings ledger as engagement vulns on the audited host when
`engagement_id` is given (scope-enforced). Sandbox returns canned
findings without touching the network.
"""

from __future__ import annotations

import http.client
import json
import logging
import socket
import ssl
from typing import Any

logger = logging.getLogger("h4k.kubelet_audit")


def _ctx() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class KubeletAuditor:
    """Read-only kubelet probes against one host:port."""

    def __init__(
        self, host: str = "127.0.0.1", port: int = 10250, timeout: float = 8.0
    ) -> None:
        host = (host or "").strip()
        if not host:
            raise ValueError("host required")
        if not 1 <= int(port) <= 65535:
            raise ValueError("port must be 1-65535")
        self.host = host
        self.port = int(port)
        self.timeout = timeout

    def _get(self, path: str) -> tuple[int | None, str]:
        """GET one path; returns (status, first-2k-of-body). Never raises."""
        conn = http.client.HTTPSConnection(
            self.host, self.port, timeout=self.timeout, context=_ctx()
        )
        try:
            conn.request("GET", path, headers={"User-Agent": "h4k-audit"})
            resp = conn.getresponse()
            return resp.status, (resp.read(2048) or b"").decode(
                "utf-8", errors="replace"
            )
        except (
            OSError,
            ssl.SSLError,
            http.client.HTTPException,
        ) as exc:
            logger.debug("kubelet GET %s failed: %s", path, exc)
            return None, str(exc)[:160]
        finally:
            conn.close()

    def audit(self) -> dict[str, Any]:
        """Run the read-only checklist; every finding names its evidence."""
        checks: list[dict[str, Any]] = []

        status, _ = self._get("/healthz")
        checks.append(
            {
                "name": "healthz",
                "reachable": status is not None,
                "severity": "INFO",
                "evidence": f"GET /healthz → {status if status is not None else 'unreachable'}",
            }
        )
        if status is None:
            return {
                "host": self.host,
                "port": self.port,
                "reachable": False,
                "checks": checks,
                "findings": [],
                "finding_count": 0,
                "secure": True,
                "note": "kubelet not reachable; nothing to audit",
            }

        status, body = self._get("/pods")
        anonymous = status == 200 and "kind" in body and "PodList" in body
        checks.append(
            {
                "name": "anonymous-pods",
                "reachable": True,
                "severity": "CRITICAL" if anonymous else "INFO",
                "evidence": f"GET /pods → {status} ({len(body)} body bytes)",
                "open": anonymous,
            }
        )

        status, body = self._get("/metrics")
        metrics = status == 200 and len(body) > 0
        checks.append(
            {
                "name": "metrics",
                "reachable": True,
                "severity": "MEDIUM" if metrics else "INFO",
                "evidence": f"GET /metrics → {status} ({len(body)} body bytes)",
                "open": metrics,
            }
        )

        readonly_open = self._readonly_port_open()
        checks.append(
            {
                "name": "readonly-port-10255",
                "reachable": True,
                "severity": "HIGH" if readonly_open else "INFO",
                "evidence": (
                    "TCP 10255 accepted a connection (insecure read-only port)"
                    if readonly_open
                    else "TCP 10255 refused/closed"
                ),
                "open": readonly_open,
            }
        )

        findings = [
            {
                "check": c["name"],
                "severity": c["severity"],
                "title": _TITLES[c["name"]],
                "evidence": c["evidence"],
            }
            for c in checks
            if c.get("open")
        ]
        return {
            "host": self.host,
            "port": self.port,
            "reachable": True,
            "checks": checks,
            "findings": findings,
            "finding_count": len(findings),
            "secure": not findings,
        }

    def _readonly_port_open(self) -> bool:
        try:
            sock = socket.create_connection((self.host, 10255), timeout=3.0)
            sock.close()
            return True
        except OSError:
            return False


_TITLES: dict[str, str] = {
    "anonymous-pods": "kubelet allows anonymous /pods (authentication disabled)",
    "metrics": "kubelet /metrics exposed without auth",
    "readonly-port-10255": "kubelet insecure read-only port 10255 open",
}


def to_ledger(
    host: str, port: int, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map audit findings to engagement vuln rows for the kubelet host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        check = str(finding.get("check") or "kubelet").strip() or "kubelet"
        rows.append(
            {
                "host": host,
                "name": f"kubelet:{port} {check}",
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "kubelet-audit",
                "reference": "",
                "cwe": "CWE-306",
                "detail": f"{finding.get('title', '')} evidence={finding.get('evidence', '')}".strip(),
            }
        )
    return rows


def sandbox_result(host: str = "127.0.0.1", port: int = 10250) -> dict[str, Any]:
    """Canned audit (no sockets opened, no network)."""
    findings = [
        {
            "check": "anonymous-pods",
            "severity": "CRITICAL",
            "title": _TITLES["anonymous-pods"],
            "evidence": "GET /pods → 200 (sandbox)",
        },
        {
            "check": "metrics",
            "severity": "MEDIUM",
            "title": _TITLES["metrics"],
            "evidence": "GET /metrics → 200 (sandbox)",
        },
    ]
    return {
        "host": host or "127.0.0.1",
        "port": port,
        "reachable": True,
        "checks": [
            {
                "name": "healthz",
                "reachable": True,
                "severity": "INFO",
                "evidence": "GET /healthz → 200 (sandbox)",
            },
            {
                "name": "anonymous-pods",
                "reachable": True,
                "severity": "CRITICAL",
                "evidence": "GET /pods → 200 (sandbox)",
                "open": True,
            },
            {
                "name": "metrics",
                "reachable": True,
                "severity": "MEDIUM",
                "evidence": "GET /metrics → 200 (sandbox)",
                "open": True,
            },
            {
                "name": "readonly-port-10255",
                "reachable": True,
                "severity": "INFO",
                "evidence": "TCP 10255 refused/closed (sandbox)",
                "open": False,
            },
        ],
        "findings": findings,
        "finding_count": len(findings),
        "secure": False,
        "sandbox": True,
    }


def parse_pod_list(body: str) -> int:
    """Count pods in a /pods body (used by tests + evidence strings)."""
    try:
        items = json.loads(body).get("items") or []
        return len(items)
    except (ValueError, AttributeError):
        return 0
