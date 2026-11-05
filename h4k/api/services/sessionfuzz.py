"""Header/cookie session fuzz — auth-bypass leads (Backlog #49).

Opt-in, explicit probing of one endpoint YOU own. The operator supplies
a working session (headers and/or cookies) plus the `authed_marker` —
a string only present in authenticated responses (e.g. "Logout") — and
optionally a `privileged_marker` (e.g. "Admin panel"). The pack replays
the baseline, then mutates identity material and diffs against the
markers:

- `strip-all` — no auth headers/cookies at all; marker still present
  means the endpoint never checks auth (CRITICAL)
- `strip-each` — drop one carrier at a time; a surviving marker names
  the redundant carrier (INFO) or a bypass (HIGH)
- `empty-value` — carriers present but empty; marker means empty is
  accepted (HIGH)
- `swap-*` — cookie/header values replaced with null/false/0/-1/true/
  admin/`undefined`; a marker means the value is not verified (HIGH),
  a privileged marker appearing means role bypass (CRITICAL)
- `inject-role-param` — `?role=admin&admin=true&is_admin=1` appended;
  privileged marker appearing means parameter pollution grants
  privilege (HIGH)

Similarity is marker-based, never fuzzy: a probe VERDICTs FINDING only
when a marker is literally present (or absent where absence is the
signal). Only the operator's `url` is ever requested. Findings ledger
as engagement vulns on the URL host when `engagement_id` is given
(scope-enforced). Sandbox returns canned probes without any request.
"""

from __future__ import annotations

import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger("h4k.sessionfuzz")

_SWAPS: list[tuple[str, str]] = [
    ("null", "null"),
    ("empty", ""),
    ("false", "false"),
    ("zero", "0"),
    ("negone", "-1"),
    ("true", "true"),
    ("admin", "admin"),
    ("undefined", "undefined"),
]

_ROLE_PARAMS = [("role", "admin"), ("admin", "true"), ("is_admin", "1")]


def _send(
    url: str,
    method: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    timeout: float,
) -> dict[str, Any]:
    """One request with explicit headers/cookies. Never raises."""
    started = time.time()
    header_map = dict(headers or {})
    if cookies:
        jar = "; ".join(f"{k}={v}" for k, v in cookies.items())
        prior = header_map.get("Cookie")
        header_map["Cookie"] = f"{prior}; {jar}" if prior else jar
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "h4k-audit", **header_map}, method=method
        )
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as resp:  # nosec B310 - operator-supplied lab target
            body = resp.read(8192).decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "body": body,
                "elapsed": round(time.time() - started, 2),
            }
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(8192).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "status": exc.code,
            "body": body,
            "elapsed": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "status": None,
            "body": "",
            "elapsed": round(time.time() - started, 2),
            "error": str(exc)[:160],
        }


def probe_session(
    url: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    authed_marker: str = "",
    privileged_marker: str = "",
    method: str = "GET",
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Replay mutated identity material; diff against the markers."""
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must be an http(s) URL you own")
    marker = (authed_marker or "").strip()
    if not marker:
        raise ValueError("authed_marker required (verdicts need a baseline signal)")
    method = (method or "GET").upper()
    if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
        raise ValueError("unsupported method")
    headers = dict(headers or {})
    cookies = dict(cookies or {})
    priv = (privileged_marker or "").strip()

    base = _send(url, method, headers, cookies, timeout)
    if base.get("error"):
        raise ValueError(f"baseline unreachable: {base['error']}")
    base_hit = marker in (base.get("body") or "")
    if not base_hit:
        return {
            "url": url,
            "probes": [],
            "probe_count": 0,
            "findings": [],
            "finding_count": 0,
            "clean": True,
            "note": "authed_marker absent from the baseline session — check the session/marker",
        }

    carriers = [("header", k) for k in headers] + [("cookie", k) for k in cookies]
    probes: list[dict[str, Any]] = []

    def _check(name: str, h: dict[str, str], c: dict[str, str]) -> dict[str, Any]:
        res = _send(url, method, h, c, timeout)
        body = res.get("body") or ""
        authed = marker in body
        priv_hit = bool(priv) and priv in body
        if priv and priv not in (base.get("body") or "") and priv_hit:
            verdict, severity = "FINDING", "CRITICAL"
            evidence = f"privileged marker appeared via {name}"
        elif authed:
            verdict, severity = "FINDING", _SEVERITY.get(name, "HIGH")
            evidence = f"authed marker survived {name}"
        else:
            verdict, severity = "SAFE", ""
            evidence = f"marker gone after {name} (auth enforced here)"
        return {
            "name": name,
            "verdict": verdict,
            "evidence": evidence,
            "severity": severity,
            "status": res.get("status"),
        }

    probes.append(_check("strip-all", {}, {}))
    for kind, key in carriers:
        h = dict(headers)
        c = dict(cookies)
        if kind == "header":
            h.pop(key, None)
        else:
            c.pop(key, None)
        probes.append(_check(f"strip-{kind}-{key}", h, c))
    for kind, key in carriers:
        h = dict(headers)
        c = dict(cookies)
        if kind == "header":
            h[key] = ""
        else:
            c[key] = ""
        probes.append(_check(f"empty-{kind}-{key}", h, c))
    for kind, key in carriers:
        for swap_name, swap_value in _SWAPS:
            h = dict(headers)
            c = dict(cookies)
            if kind == "header":
                h[key] = swap_value
            else:
                c[key] = swap_value
            probes.append(_check(f"swap-{kind}-{key}-{swap_name}", h, c))

    parts = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    for rk, rv in _ROLE_PARAMS:
        query[rk] = rv
    polluted = urllib.parse.urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            urllib.parse.urlencode(query),
            parts.fragment,
        )
    )
    res = _send(polluted, method, headers, cookies, timeout)
    priv_hit = bool(priv) and priv in (res.get("body") or "")
    if priv and priv not in (base.get("body") or "") and priv_hit:
        verdict, severity = "FINDING", "HIGH"
        evidence = "privileged marker appeared via role query params"
    else:
        verdict, severity = "SAFE", ""
        evidence = "role query params granted nothing new"
    probes.append(
        {
            "name": "inject-role-param",
            "verdict": verdict,
            "evidence": evidence,
            "severity": severity,
            "status": res.get("status"),
        }
    )

    findings = [
        {
            "probe": p["name"],
            "severity": p["severity"],
            "title": _TITLES.get(
                p["name"].split("-")[0], f"auth bypass via {p['name']}"
            ),
            "evidence": p["evidence"],
        }
        for p in probes
        if p["verdict"] == "FINDING"
    ]
    return {
        "url": url,
        "carriers": [f"{k}:{v}" for k, v in carriers],
        "probes": probes,
        "probe_count": len(probes),
        "findings": findings,
        "finding_count": len(findings),
        "clean": not findings,
    }


_SEVERITY: dict[str, str] = {"strip-all": "CRITICAL"}

_TITLES: dict[str, str] = {
    "strip": "endpoint answers without any auth material",
    "empty": "endpoint accepts empty auth values",
    "swap": "endpoint does not verify auth values",
    "inject": "role query parameters grant privilege",
}


def to_ledger(
    host: str, url: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map bypass findings to engagement vuln rows for the URL host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        rows.append(
            {
                "host": host,
                "name": f"session-fuzz {finding.get('probe')} via {url}"[:220],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "session-fuzz",
                "reference": "",
                "cwe": "CWE-287",
                "detail": str(finding.get("evidence", ""))[:400],
            }
        )
    return rows


def sandbox_result(url: str = "http://lab.local/private") -> dict[str, Any]:
    """Canned pack result (no requests sent)."""
    probes = [
        {
            "name": "strip-all",
            "verdict": "FINDING",
            "evidence": "authed marker survived strip-all (sandbox)",
            "severity": "CRITICAL",
            "status": 200,
        },
        {
            "name": "strip-cookie-session",
            "verdict": "SAFE",
            "evidence": "marker gone after strip-cookie-session (sandbox)",
            "severity": "",
            "status": 401,
        },
        {
            "name": "swap-cookie-session-admin",
            "verdict": "FINDING",
            "evidence": "authed marker survived swap-cookie-session-admin (sandbox)",
            "severity": "HIGH",
            "status": 200,
        },
    ]
    findings = [
        {
            "probe": "strip-all",
            "severity": "CRITICAL",
            "title": "endpoint answers without any auth material",
            "evidence": probes[0]["evidence"],
        },
        {
            "probe": "swap-cookie-session-admin",
            "severity": "HIGH",
            "title": "endpoint does not verify auth values",
            "evidence": probes[2]["evidence"],
        },
    ]
    return {
        "url": url or "http://lab.local/private",
        "carriers": ["cookie:session"],
        "probes": probes,
        "probe_count": len(probes),
        "findings": findings,
        "finding_count": len(findings),
        "clean": False,
        "sandbox": True,
    }
