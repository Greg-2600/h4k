"""OpenAPI import → fuzz — spec-driven targets (Backlog #48).

Opt-in, lab-only fuzzing driven by a pasted OpenAPI 3 / Swagger 2.0
document (JSON or YAML — parsed, never fetched). The importer walks
paths, parameters and JSON request-body schemas into concrete targets;
the fuzzer rebuilds each target with type-correct dummy values, then
replays one mutated field per iteration (round-robin — deterministic
by construction, no RNG) and records crash signals: HTTP 5xx, stack
traces or SQL fragments in the body, and timeouts.

Only the operator-supplied `base_url` is ever requested, with
operator-supplied headers (e.g. an Authorization token for an owned
lab app). Findings ledger as engagement vulns on the base host when
`engagement_id` is given (scope-enforced). Sandbox returns a canned
import + candidates without parsing or requesting anything.
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

import yaml

logger = logging.getLogger("h4k.openapi_fuzz")

_ERROR_RE = re.compile(
    r"traceback|exception|stack trace|sql syntax|psql|pg_|ora-\d+|"
    r"sqlite|mongodb|NullPointer|panic:|query failed",
    re.IGNORECASE,
)


def loads_spec(text: str) -> dict[str, Any]:
    """Parse pasted JSON or YAML text into a spec object (400-worthy errors)."""
    text = (text or "").strip()
    if not text:
        raise ValueError("spec required (paste the OpenAPI document)")
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"spec is not JSON or YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError("spec must be a JSON/YAML object")
    return doc


def parse_spec(doc: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten an OpenAPI 3 / Swagger 2.0 document into fuzz targets."""
    if not isinstance(doc, dict):
        raise ValueError("spec must be a JSON/YAML object")
    paths = doc.get("paths")
    if not isinstance(paths, dict) or not paths:
        raise ValueError("spec has no paths to fuzz")
    defs = (
        doc.get("components", {}).get("schemas", {})
        if isinstance(doc.get("components"), dict)
        else {}
    )
    if not defs and isinstance(doc.get("definitions"), dict):
        defs = doc["definitions"]
    targets: list[dict[str, Any]] = []
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = [p for p in (item.get("parameters") or []) if isinstance(p, dict)]
        for method, op in item.items():
            if method.lower() not in (
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
            ):
                continue
            if not isinstance(op, dict):
                continue
            params: list[dict[str, Any]] = []
            for p in shared + [
                p for p in (op.get("parameters") or []) if isinstance(p, dict)
            ]:
                params.append(
                    {
                        "name": str(p.get("name") or ""),
                        "in": str(p.get("in") or "query"),
                        "schema": p.get("schema") or {"type": p.get("type", "string")},
                    }
                )
            params = [p for p in params if p["name"]]
            body_fields: list[dict[str, Any]] = []
            body = op.get("requestBody") or {}
            content = (body.get("content") or {}) if isinstance(body, dict) else {}
            schema = (content.get("application/json") or {}).get("schema") or {}
            if not schema and op.get("consumes"):
                for p in op.get("parameters") or []:
                    if isinstance(p, dict) and p.get("in") == "body":
                        schema = p.get("schema") or {}
            body_fields = _flatten_schema(schema, defs)
            targets.append(
                {
                    "method": method.upper(),
                    "path": str(path),
                    "params": params[:16],
                    "body_fields": body_fields[:32],
                    "operation": str(
                        op.get("operationId") or f"{method.upper()} {path}"
                    ),
                }
            )
    if not targets:
        raise ValueError("spec paths hold no fuzzable operations")
    return targets


def _resolve(node: Any, defs: dict[str, Any], depth: int = 0) -> Any:
    if depth > 4 or not isinstance(node, dict):
        return node
    ref = str(node.get("$ref") or "")
    if ref.startswith("#/components/schemas/"):
        return _resolve(defs.get(ref.split("/")[-1], {}), defs, depth + 1)
    if ref.startswith("#/definitions/"):
        return _resolve(defs.get(ref.split("/")[-1], {}), defs, depth + 1)
    return node


def _flatten_schema(
    schema: Any, defs: dict[str, Any], prefix: str = "", depth: int = 0
) -> list[dict[str, Any]]:
    schema = _resolve(schema, defs)
    if not isinstance(schema, dict) or depth > 3:
        return []
    stype = str(schema.get("type") or "object")
    if stype == "array":
        return _flatten_schema(schema.get("items"), defs, prefix + "[]", depth + 1)
    if stype != "object":
        return (
            [
                {
                    "path": prefix or "value",
                    "type": stype,
                    "schema": schema if prefix else {},
                }
            ]
            if prefix
            else []
        )
    fields: list[dict[str, Any]] = []
    props = schema.get("properties") or {}
    if not isinstance(props, dict):
        return fields
    for name, subschema in props.items():
        sub = _resolve(subschema, defs)
        dotted = f"{prefix}.{name}" if prefix else str(name)
        if isinstance(sub, dict) and str(sub.get("type", "object")) == "object":
            fields.extend(_flatten_schema(sub, defs, dotted, depth + 1))
        elif isinstance(sub, dict) and sub.get("type") == "array":
            fields.append({"path": dotted, "type": "array", "schema": sub})
        else:
            fields.append(
                {
                    "path": dotted,
                    "type": (
                        str((sub or {}).get("type", "string"))
                        if isinstance(sub, dict)
                        else "string"
                    ),
                    "schema": sub if isinstance(sub, dict) else {},
                }
            )
    return fields


def _dummy_value(field: dict[str, Any]) -> Any:
    ftype = field.get("type", "string")
    schema = field.get("schema") or {}
    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("example"), (str, int, float, bool)):
        return schema["example"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    return {"string": "test", "integer": 1, "number": 1.5, "boolean": True}.get(
        ftype, "test"
    )


def build_request(
    base: str, target: dict[str, Any], headers: dict[str, str] | None = None
) -> tuple[str, str, bytes | None, dict[str, str]]:
    """Baseline request: templated path, dummy params, dummy JSON body."""
    method = target["method"]
    path = target["path"]
    query: dict[str, str] = {}
    hds: dict[str, str] = dict(headers or {})
    for param in target.get("params", []):
        dummy = _dummy_value(
            {
                "type": (param.get("schema") or {}).get("type", "string"),
                "schema": param.get("schema") or {},
            }
        )
        where = param.get("in", "query")
        if where == "path":
            path = path.replace("{" + param["name"] + "}", str(dummy))
            path = re.sub(r"\{[^}]*\}", "1", path)
        elif where == "query":
            query[param["name"]] = str(dummy)
        elif where == "header":
            hds[param["name"]] = str(dummy)
    path = re.sub(r"\{[^}]*\}", "1", path)
    body: bytes | None = None
    if method in ("POST", "PUT", "PATCH") and target.get("body_fields"):
        obj: dict[str, Any] = {}
        for field in target["body_fields"]:
            obj[field["path"]] = _dummy_value(field)
        body = json.dumps(obj).encode()
        hds.setdefault("Content-Type", "application/json")
    url = base.rstrip("/") + "/" + path.lstrip("/")
    if query:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(query)
    return method, url, body, hds


_MUTATIONS: list[tuple[str, Any]] = [
    ("oversize", lambda _v: "A" * 4096),
    ("empty", lambda _v: ""),
    ("null", lambda _v: None),
    ("wrong-type", lambda v: {"_": v} if not isinstance(v, dict) else [v]),
    ("format", lambda _v: "%s %x %n ${7*7}"),
    ("sqli", lambda _v: "' OR '1'='1"),
    ("traversal", lambda _v: "../../../../../../etc/passwd"),
    ("negative", lambda _v: -1),
    ("huge-int", lambda _v: 10**30),
    ("bool-flip", lambda v: (not v) if isinstance(v, bool) else True),
]


def _send(
    method: str, url: str, body: bytes | None, headers: dict[str, str], timeout: float
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
            "elapsed": round(time.time() - started, 2),
        }
    except Exception as exc:
        return {
            "status": None,
            "body": "",
            "elapsed": round(time.time() - started, 2),
            "error": str(exc)[:160],
        }


def fuzz_targets(
    base: str,
    targets: list[dict[str, Any]],
    headers: dict[str, str] | None = None,
    iterations: int = 40,
    timeout: float = 8.0,
    progress: Any = None,
) -> dict[str, Any]:
    """Replay one mutated field per iteration, round-robin (deterministic)."""
    base = (base or "").rstrip("/")
    if not targets:
        raise ValueError("no targets to fuzz")
    iterations = max(1, min(int(iterations or 40), 200))
    candidates: list[dict[str, Any]] = []
    sent = 0
    for i in range(iterations):
        target = targets[i % len(targets)]
        method, url, body, hds = build_request(base, target, headers)
        # Pick the field + mutation by rotation.
        fields = (
            [
                f"query:{p['name']}"
                for p in target.get("params", [])
                if p.get("in") in ("query", "path")
            ]
            + [f"body:{f['path']}" for f in target.get("body_fields", [])]
        ) or ["query:_"]
        field = fields[(i // max(len(targets), 1)) % len(fields)]
        mut_name, mut_fn = _MUTATIONS[(i // max(len(fields), 1)) % len(_MUTATIONS)]
        value: Any = None
        try:
            parts = urllib.parse.urlsplit(url)
            query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
            obj = json.loads(body.decode()) if body else {}
            if field.startswith("body:"):
                obj[field[5:]] = mut_fn(obj.get(field[5:], "test"))
                body = json.dumps(obj).encode()
                value = obj[field[5:]]
            else:
                key = field[6:]
                if key == "_":
                    key = "q"
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
        except (ValueError, TypeError, KeyError) as exc:
            logger.debug("mutation skipped: %s", exc)
            continue
        res = _send(method, url, body, hds, timeout)
        sent += 1
        signal, evidence = _signal(res)
        if signal != "none":
            candidates.append(
                {
                    "target": f"{method} {target['path']}",
                    "mutation": f"{mut_name}@{field}",
                    "sent": str(value)[:120],
                    "signal": signal,
                    "evidence": evidence[:200],
                    "status": res.get("status"),
                }
            )
        if progress and (i + 1) % 10 == 0:
            progress(f"openapi fuzz {i + 1}/{iterations}", (i + 1) / iterations * 100.0)
    return {
        "base": base,
        "targets": len(targets),
        "iterations": sent,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": not candidates,
    }


def _signal(res: dict[str, Any]) -> tuple[str, str]:
    if res.get("error"):
        message = str(res["error"])
        if "timed out" in message or "Timeout" in message:
            return "timeout", message[:160]
        return "dropped", message[:160]
    status = res.get("status") or 0
    body = res.get("body") or ""
    if status >= 500:
        return "server-error", f"HTTP {status} on mutated input"
    match = _ERROR_RE.search(body)
    if match:
        return "error-text", f"server leaked: …{match.group(0)[:60]}…"
    return "none", "clean reply"


def to_ledger(
    host: str, base: str, candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map fuzz crash signals to engagement vuln rows for the base host."""
    rows: list[dict[str, Any]] = []
    for cand in candidates:
        rows.append(
            {
                "host": host,
                "name": f"openapi-fuzz {cand.get('mutation')} on {cand.get('target')}"[
                    :220
                ],
                "severity": (
                    "HIGH"
                    if cand.get("signal") in ("server-error", "dropped")
                    else "MEDIUM"
                ),
                "module": "openapi-fuzz",
                "reference": "",
                "cwe": "CWE-20",
                "detail": (
                    f"base={base} sent={cand.get('sent', '')} "
                    f"evidence={cand.get('evidence', '')}"
                ).strip()[:400],
            }
        )
    return rows


def sandbox_result(base: str = "http://lab.local") -> dict[str, Any]:
    """Canned import + fuzz (nothing parsed, nothing requested)."""
    candidates = [
        {
            "target": "GET /items/{id}",
            "mutation": "sqli@query:q",
            "sent": "' OR '1'='1",
            "signal": "server-error",
            "evidence": "HTTP 500 on mutated input (sandbox)",
            "status": 500,
        },
        {
            "target": "POST /items",
            "mutation": "format@body:name",
            "sent": "%s %x %n ${7*7}",
            "signal": "error-text",
            "evidence": "server leaked: …exception… (sandbox)",
            "status": 200,
        },
    ]
    return {
        "base": base or "http://lab.local",
        "targets": 3,
        "iterations": 8,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": False,
        "sandbox": True,
    }
