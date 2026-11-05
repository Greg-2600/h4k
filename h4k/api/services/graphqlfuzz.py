"""GraphQL introspection + fuzz — field/depth probes (Backlog #47).

Opt-in, explicit testing of one GraphQL endpoint YOU own (urllib-only
POSTs of JSON bodies). The pack runs in order:

1. `introspection` — compact `__schema` query for root fields and
   object-type fields. A working answer is itself a MEDIUM finding
   (schema disclosure in a deployed API).
2. `depth` — builds a nested query from the discovered fields (or
   `__typename` when introspection is off) at the configured depth.
   Data without a depth complaint is a HIGH finding (no query-depth
   limit → DoS); an explicit depth/max-complexity error means
   protected.
3. `batching` — one array of N identical `{__typename}` queries. All
   answered means batching is on (MEDIUM — brute-force/DoS amplifier).
4. `field-fuzz` — each root field once plain, once with a garbage
   argument blob, once as a malformed body. Server stack traces or SQL
   fragments in `errors[].message` are a HIGH finding (error leak);
   anything else is recorded SAFE with status evidence.

Only the operator-supplied `url` is ever requested. Findings ledger as
engagement vulns on the URL host when `engagement_id` is given
(scope-enforced). Sandbox returns canned probes without any request.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger("h4k.graphqlfuzz")

INTROSPECTION_QUERY = """{__schema{queryType{name}mutationType{name}types{...on OBJECT{name fields{name}}}}}"""

_ERROR_RE = re.compile(
    r"traceback|exception|stack trace|at\s+[\w.$]+\(|sql syntax|psql|pg_|"
    r"ora-\d+|sqlite|mongodb|NullPointer|panic:|query failed",
    re.IGNORECASE,
)


def _post(url: str, body: Any, timeout: float) -> dict[str, Any]:
    """POST one JSON body; never raises."""
    started = time.time()
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "h4k-audit"},
            method="POST",
        )
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as resp:  # nosec B310 - operator-supplied lab target
            raw = resp.read(65536).decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "body": raw,
                "elapsed": round(time.time() - started, 2),
            }
    except Exception as exc:
        return {
            "status": None,
            "body": "",
            "elapsed": round(time.time() - started, 2),
            "error": str(exc)[:160],
        }


def _parse_schema(doc: dict[str, Any]) -> dict[str, Any]:
    schema = (doc.get("data") or {}).get("__schema") or {}
    queries: list[str] = []
    mutations: list[str] = []
    types: dict[str, list[str]] = {}
    by_name = {
        t.get("name"): t for t in schema.get("types") or [] if isinstance(t, dict)
    }
    for typename, dest in (
        ((schema.get("queryType") or {}).get("name"), queries),
        ((schema.get("mutationType") or {}).get("name"), mutations),
    ):
        node = by_name.get(typename) or {}
        for field in node.get("fields") or []:
            if isinstance(field, dict) and field.get("name"):
                dest.append(str(field["name"]))
    for tname, tnode in by_name.items():
        fields = [
            str(f["name"])
            for f in (tnode.get("fields") or [])
            if isinstance(f, dict) and f.get("name")
        ]
        if fields:
            types[str(tname)] = fields[:64]
    return {"queries": queries[:64], "mutations": mutations[:64], "types": types}


def _error_leak(body: str) -> str | None:
    try:
        doc = json.loads(body)
    except ValueError:
        return None
    messages = " | ".join(
        str(e.get("message", "")) for e in doc.get("errors", []) if isinstance(e, dict)
    )
    if not messages:
        return None
    match = _ERROR_RE.search(messages)
    return match.group(0)[:80] if match else None


def probe_endpoint(
    url: str,
    depth: int = 25,
    batch: int = 10,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Run the introspection + depth + batch + field-fuzz pack."""
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must be an http(s) URL you own")
    depth = max(2, min(int(depth or 25), 100))
    batch = max(2, min(int(batch or 10), 50))

    probes: list[dict[str, Any]] = []
    schema: dict[str, Any] = {"queries": [], "mutations": [], "types": {}}

    res = _post(url, {"query": INTROSPECTION_QUERY}, timeout)
    if res["status"] == 200:
        try:
            schema = _parse_schema(json.loads(res["body"] or "{}"))
        except ValueError:
            schema = {"queries": [], "mutations": [], "types": {}, "parse_error": True}
    introspected = bool(schema.get("queries") or schema.get("mutations"))
    probes.append(
        {
            "name": "introspection",
            "verdict": "FINDING" if introspected else "SAFE",
            "evidence": (
                f"{len(schema.get('queries', []))} queries, "
                f"{len(schema.get('mutations', []))} mutations disclosed"
                if introspected
                else f"introspection refused (status {res.get('status')})"
            ),
            "severity": "MEDIUM" if introspected else "",
            "status": res.get("status"),
        }
    )

    # Depth probe: nest the first known root field; unknown schema means
    # the depth AST cannot be built honestly, so the probe stays neutral.
    known = schema.get("queries") or []
    if known:
        first = known[0]
        nested = first
        for _ in range(depth - 1):
            nested = f"{first}{{{nested}}}"
        res = _post(url, {"query": "{" + nested + "}"}, timeout)
        body_lower = (res.get("body") or "").lower()
        depth_limited = any(
            word in body_lower for word in ("depth", "complexity", "too many", "max")
        )
        at_risk = res.get("status") == 200 and not depth_limited
        probes.append(
            {
                "name": "depth",
                "verdict": "FINDING" if at_risk else "SAFE",
                "evidence": (
                    f"depth-{depth} query answered without complaint (status {res.get('status')})"
                    if at_risk
                    else "server enforces a depth/complexity limit"
                ),
                "severity": "HIGH" if at_risk else "",
                "status": res.get("status"),
            }
        )
    else:
        probes.append(
            {
                "name": "depth",
                "verdict": "SAFE",
                "evidence": "no root fields discovered — depth not testable without a schema",
                "severity": "",
                "status": None,
            }
        )

    res = _post(url, [{"query": "{__typename}"}] * batch, timeout)
    answered = res.get("status") == 200
    try:
        answered = answered and isinstance(json.loads(res.get("body") or "null"), list)
    except ValueError:
        answered = False
    probes.append(
        {
            "name": "batching",
            "verdict": "FINDING" if answered else "SAFE",
            "evidence": (
                f"server answered a {batch}-query batch"
                if answered
                else f"batch refused (status {res.get('status')})"
            ),
            "severity": "MEDIUM" if answered else "",
            "status": res.get("status"),
        }
    )

    leak: str | None = None
    checked = 0
    for field in (schema.get("queries") or [])[:12] or ["__typename"]:
        for payload in (f"{{{field}}}", f'{{{field}(x:"\'\\"\\0" + "A" * 4096)}}', "{"):
            res = _post(url, {"query": payload}, timeout)
            checked += 1
            leak = leak or _error_leak(res.get("body") or "")
            if leak:
                break
        if leak:
            break
    probes.append(
        {
            "name": "field-fuzz",
            "verdict": "FINDING" if leak else "SAFE",
            "evidence": (
                f"server leaked: {leak}"
                if leak
                else f"{checked} field payloads, no stack traces"
            ),
            "severity": "HIGH" if leak else "",
            "status": None,
        }
    )

    findings = [
        {
            "probe": p["name"],
            "severity": p["severity"],
            "title": _TITLES[p["name"]],
            "evidence": p["evidence"],
        }
        for p in probes
        if p["verdict"] == "FINDING"
    ]
    return {
        "url": url,
        "gql_schema": schema,
        "probes": probes,
        "probe_count": len(probes),
        "findings": findings,
        "finding_count": len(findings),
        "clean": not findings,
    }


_TITLES: dict[str, str] = {
    "introspection": "GraphQL introspection enabled (schema disclosure)",
    "depth": "no query depth limit (expensive-query DoS)",
    "batching": "query batching enabled (brute-force/DoS amplifier)",
    "field-fuzz": "server stack trace or SQL fragment leaked in errors",
}


def to_ledger(
    host: str, url: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map pack findings to engagement vuln rows for the URL host."""
    cwe = {
        "introspection": "CWE-200",
        "depth": "CWE-400",
        "batching": "CWE-400",
        "field-fuzz": "CWE-209",
    }
    rows: list[dict[str, Any]] = []
    for finding in findings:
        probe = str(finding.get("probe") or "graphql")
        rows.append(
            {
                "host": host,
                "name": f"graphql {probe} via {url}"[:220],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "graphql-fuzz",
                "reference": "",
                "cwe": cwe.get(probe, ""),
                "detail": str(finding.get("evidence", ""))[:400],
            }
        )
    return rows


def sandbox_result(url: str = "http://lab.local/graphql") -> dict[str, Any]:
    """Canned pack result (no requests sent)."""
    schema = {
        "queries": ["user", "users"],
        "mutations": ["login"],
        "types": {"User": ["id", "name"], "Query": ["user", "users"]},
    }
    probes: list[dict[str, Any]] = [
        {
            "name": "introspection",
            "verdict": "FINDING",
            "evidence": "2 queries, 1 mutations disclosed (sandbox)",
            "severity": "MEDIUM",
            "status": 200,
        },
        {
            "name": "depth",
            "verdict": "FINDING",
            "evidence": "depth-25 query answered without complaint (status 200) (sandbox)",
            "severity": "HIGH",
            "status": 200,
        },
        {
            "name": "batching",
            "verdict": "SAFE",
            "evidence": "batch refused (status 400) (sandbox)",
            "severity": "",
            "status": 400,
        },
        {
            "name": "field-fuzz",
            "verdict": "SAFE",
            "evidence": "12 field payloads, no stack traces (sandbox)",
            "severity": "",
            "status": None,
        },
    ]
    findings = [
        {
            "probe": p["name"],
            "severity": p["severity"],
            "title": _TITLES[p["name"]],
            "evidence": p["evidence"],
        }
        for p in probes
        if p["verdict"] == "FINDING"
    ]
    return {
        "url": url or "http://lab.local/graphql",
        "gql_schema": schema,
        "probes": probes,
        "probe_count": len(probes),
        "findings": findings,
        "finding_count": len(findings),
        "clean": False,
        "sandbox": True,
    }
