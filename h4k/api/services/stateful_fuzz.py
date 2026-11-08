"""Stateful fuzz — login → authed-flow fuzz (Backlog #56).

Opt-in, lab-only fuzzing of multi-step flows that need a session.
Each iteration logs in fresh with the operator's credentials, harvests
the session (every `Set-Cookie` plus one optional JSON field promoted
to `Authorization: Bearer`), then replays ONE fuzzed flow step with
the session attached (round-robin over steps × fields × mutations —
deterministic, no RNG).

Signals are HTTP 5xx, stack-trace/SQL fragments in the body, and
timeouts; a lost session marker (optional `authed_marker`) is
reported per candidate but never verdicts on its own. Only the
operator's `login_url` and flow URLs are ever requested. Findings
ledger as engagement vulns on the flow host when `engagement_id` is
given (scope-enforced). Sandbox returns canned candidates without
any request.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger("h4k.statefulfuzz")

_ERROR_RE = re.compile(
    r"traceback|exception|stack trace|sql syntax|psql|pg_|ora-\d+|"
    r"sqlite|mongodb|NullPointer|panic:|query failed",
    re.IGNORECASE,
)

_MUTATIONS: list[tuple[str, Any]] = [
    ("oversize", lambda _v: "A" * 4096),
    ("empty", lambda _v: ""),
    ("null", lambda _v: None),
    ("format", lambda _v: "%s %x %n ${7*7}"),
    ("sqli", lambda _v: "' OR '1'='1"),
    ("traversal", lambda _v: "../../../../../../etc/passwd"),
]


def _send(
    url: str, method: str, body: bytes | None, headers: dict[str, str], timeout: float
) -> dict[str, Any]:
    started = time.time()
    try:
        req = urllib.request.Request(
            url,
            data=body,
            headers={"User-Agent": "h4k-audit", **headers},
            method=method,
        )
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as resp:  # nosec B310 - operator-supplied lab target
            raw = resp.read(8192).decode("utf-8", errors="replace")
            return {
                "status": resp.status,
                "body": raw,
                "cookies": resp.headers.get_all("Set-Cookie") or [],
                "elapsed": round(time.time() - started, 2),
            }
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(8192).decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        return {
            "status": exc.code,
            "body": raw,
            "cookies": (exc.headers.get_all("Set-Cookie") or []) if exc.headers else [],
            "elapsed": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "status": None,
            "body": "",
            "cookies": [],
            "elapsed": round(time.time() - started, 2),
            "error": str(exc)[:160],
        }


def _json_field(doc: Any, path: str) -> Any:
    node = doc
    for part in (path or "").split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, (str, int, float, bool)) else None


def login(
    url: str,
    method: str = "POST",
    body: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    json_field: str = "",
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Log in once; harvest cookies + one optional JSON token field."""
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("login_url must be an http(s) URL you own")
    payload = json.dumps(body or {}).encode()
    hds = dict(headers or {})
    hds.setdefault("Content-Type", "application/json")
    res = _send(url, method.upper(), payload, hds, timeout)
    if res.get("error"):
        raise ValueError(f"login unreachable: {res['error']}")
    if (res.get("status") or 0) >= 400:
        raise ValueError(f"login refused (status {res.get('status')})")
    cookies: dict[str, str] = {}
    for header in res.get("cookies", []) or []:
        pair = header.split(";", 1)[0]
        if "=" in pair:
            key, _, value = pair.partition("=")
            cookies[key.strip()] = value.strip()
    token: str | None = None
    if json_field:
        try:
            token = _json_field(json.loads(res.get("body") or "{}"), json_field)
        except ValueError:
            token = None
    return {"cookies": cookies, "token": str(token) if token else ""}


def fuzz_flow(
    login_url: str,
    login_body: dict[str, Any] | None = None,
    login_headers: dict[str, str] | None = None,
    login_method: str = "POST",
    session_json_field: str = "",
    authed_marker: str = "",
    steps: list[dict[str, Any]] | None = None,
    iterations: int = 30,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Login per iteration, replay one mutated authed step, collect signals."""
    if not steps:
        raise ValueError("flow steps required (at least one method + url)")
    clean_steps: list[dict[str, Any]] = []
    for step in steps:
        if not isinstance(step, dict) or not str(step.get("url") or "").strip():
            raise ValueError("each flow step needs at least a url")
        clean_steps.append(
            {
                "method": str(step.get("method") or "GET").upper(),
                "url": str(step["url"]).strip(),
                "fields": [str(f) for f in (step.get("fields") or [])][:16],
                "body": step.get("body") if isinstance(step.get("body"), dict) else {},
            }
        )
    iterations = max(1, min(int(iterations or 30), 200))
    candidates: list[dict[str, Any]] = []
    logins = 0
    sent = 0
    for i in range(iterations):
        try:
            session = login(
                login_url,
                method=login_method,
                body=login_body,
                headers=login_headers,
                json_field=session_json_field,
                timeout=timeout,
            )
        except ValueError as exc:
            raise ValueError(f"iteration {i}: {exc}") from exc
        logins += 1
        step = clean_steps[i % len(clean_steps)]
        fields = step["fields"] or ["_query_q"]
        field = fields[(i // max(len(clean_steps), 1)) % len(fields)]
        mut_name, mut_fn = _MUTATIONS[(i // max(len(fields), 1)) % len(_MUTATIONS)]
        parts = urllib.parse.urlsplit(step["url"])
        query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
        obj = dict(step["body"])
        value: Any = None
        if field.startswith("body:"):
            key = field[5:]
            value = mut_fn(obj.get(key, "test"))
            obj[key] = value
        else:
            key = field[6:] if field.startswith("query:") else field
            value = mut_fn(query.get(key, "test"))
            query[key] = (
                ""
                if value is None
                else (value if isinstance(value, str) else json.dumps(value))
            )
        url = urllib.parse.urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                parts.path,
                urllib.parse.urlencode(query),
                parts.fragment,
            )
        )
        body = json.dumps(obj).encode() if obj else None
        headers: dict[str, str] = {}
        if session["cookies"]:
            headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in session["cookies"].items()
            )
        if session["token"]:
            headers["Authorization"] = f"Bearer {session['token']}"
        if body is not None:
            headers["Content-Type"] = "application/json"
        res = _send(url, step["method"], body, headers, timeout)
        sent += 1
        signal, evidence = _signal(res, authed_marker)
        if signal != "none":
            candidates.append(
                {
                    "step": f"{step['method']} {step['url']}",
                    "mutation": f"{mut_name}@{field}",
                    "sent": str(value)[:120],
                    "signal": signal,
                    "evidence": evidence[:200],
                    "status": res.get("status"),
                }
            )
    return {
        "steps": len(clean_steps),
        "logins": logins,
        "iterations": sent,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": not candidates,
    }


def _signal(res: dict[str, Any], authed_marker: str) -> tuple[str, str]:
    if res.get("error"):
        message = str(res["error"])
        if "timed out" in message or "Timeout" in message:
            return "timeout", message[:160]
        return "dropped", message[:160]
    status = res.get("status") or 0
    body = res.get("body") or ""
    if status >= 500:
        return "server-error", f"HTTP {status} on mutated authed request"
    match = _ERROR_RE.search(body)
    if match:
        return "error-text", f"server leaked: …{match.group(0)[:60]}…"
    if authed_marker and authed_marker not in body:
        return "session-lost", "authed marker missing after mutation (auth wall?)"
    return "none", "clean reply (session held)"


def to_ledger(
    host: str, base: str, candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map fuzz crash signals to engagement vuln rows for the flow host."""
    rows: list[dict[str, Any]] = []
    for cand in candidates:
        if cand.get("signal") == "session-lost":
            continue  # auth wall, not a bug
        rows.append(
            {
                "host": host,
                "name": f"stateful-fuzz {cand.get('mutation')} on {cand.get('step')}"[
                    :220
                ],
                "severity": (
                    "HIGH"
                    if cand.get("signal") in ("server-error", "dropped")
                    else "MEDIUM"
                ),
                "module": "stateful-fuzz",
                "reference": "",
                "cwe": "CWE-20",
                "detail": f"sent={cand.get('sent', '')} evidence={cand.get('evidence', '')}".strip()[
                    :400
                ],
            }
        )
    return rows


def sandbox_result(base: str = "http://lab.local") -> dict[str, Any]:
    """Canned login + fuzz (no requests sent)."""
    candidates = [
        {
            "step": "POST http://lab.local/items",
            "mutation": "sqli@body:name",
            "sent": "' OR '1'='1",
            "signal": "server-error",
            "evidence": "HTTP 500 on mutated authed request (sandbox)",
            "status": 500,
        },
        {
            "step": "GET http://lab.local/items",
            "mutation": "format@query:q",
            "sent": "%s %x %n ${7*7}",
            "signal": "error-text",
            "evidence": "server leaked: …exception… (sandbox)",
            "status": 200,
        },
    ]
    return {
        "url": base or "http://lab.local",
        "base": base or "http://lab.local",
        "steps": 2,
        "logins": 8,
        "iterations": 8,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": False,
        "sandbox": True,
    }
