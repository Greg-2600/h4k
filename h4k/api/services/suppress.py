"""Inline suppress — NOSAST with expiry + owner (Backlog #67).

Findings can be waived where they are written about: a comment holding
a `NOSAST` directive on the finding's line (or the line directly
above, Semgrep-style) suppresses it — bare `NOSAST` covers any rule,
`NOSAST: rule-id[,rule2]` covers named rules only. Directives carry
`owner=` and `expires=YYYY-MM-DD`; an expired waiver stops applying
and is reported in `expired` so a lapsed waiver never vanishes
quietly, and a malformed `expires=` is a 400 (a waiver that can't be
parsed must shout, never silently apply). No `expires=` means no
expiry — permanent, owner still recorded.

Read-only and offline: sources stay server-side for the call only,
nothing ledgers. Sandbox returns a canned match.
"""

from __future__ import annotations

import datetime as _dt
import logging
import re
from typing import Any

logger = logging.getLogger("h4k.suppress")

_KV = re.compile(r"(owner|expires|reason)\s*=\s*", re.IGNORECASE)
_KEY_BOUND = re.compile(r"\s+(owner|expires|reason)\s*=", re.IGNORECASE)


def _split_kv(rest: str) -> dict[str, str]:
    """Split `owner=.. expires=.. reason=..` on key boundaries."""
    out: dict[str, str] = {}
    for m in _KV.finditer(rest):
        key = m.group(1).lower()
        if key in out:
            continue
        nxt = _KEY_BOUND.search(rest, m.end())
        val = rest[m.end() : nxt.start() if nxt else len(rest)]
        val = val.strip().rstrip("*/").strip()
        out[key] = val
    return out


_WORD = re.compile(r"(?<![A-Za-z0-9_])NOSAST")


def _today() -> _dt.date:
    return _dt.date.today()


def parse_directives(path: str, content: str) -> list[dict[str, Any]]:
    """Find NOSAST directives in one source text (1-based line numbers)."""
    if not isinstance(content, str):
        raise ValueError(f"file {path!r}: content must be text")
    found: list[dict[str, Any]] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        m = _WORD.search(line)
        if m is None:
            continue
        tail = line[m.end() :]
        rules: list[str] = []
        rest = tail
        rm = re.match(
            r"\s*:\s*([A-Za-z0-9_.,\-\s]+?)(?=\s+(?:owner|expires|reason)\s*=|\s*$)",
            tail,
            re.IGNORECASE,
        )
        if rm:
            rules = [r.strip().lower() for r in rm.group(1).split(",") if r.strip()]
            rest = tail[rm.end() :]
        owner = ""
        expires = ""
        reason = ""
        kv = _split_kv(rest)
        owner = kv.get("owner", "")
        expires = kv.get("expires", "")
        reason = kv.get("reason", "")
        expiry: _dt.date | None = None
        if expires:
            try:
                expiry = _dt.date.fromisoformat(expires)
            except ValueError as exc:
                raise ValueError(
                    f"{path}:{lineno}: expires={expires!r} is not YYYY-MM-DD"
                ) from exc
        found.append(
            {
                "file": path,
                "line": lineno,
                "rules": rules,
                "owner": owner,
                "expires": expires,
                "reason": reason,
                "expired": expiry is not None and expiry < _today(),
            }
        )
    return found


def _check_finding(finding: Any, index: int) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise ValueError(f"findings[{index}]: must be an object")
    try:
        line = int(finding.get("line", 0) or 0)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"findings[{index}]: line must be a number") from exc
    return {
        "rule_id": str(finding.get("rule_id") or "unknown"),
        "name": str(finding.get("name") or finding.get("rule_id") or "finding"),
        "severity": str(finding.get("severity") or "info").strip().lower(),
        "cwe": str(finding.get("cwe") or ""),
        "file": str(finding.get("file") or "?"),
        "line": line,
    }


def match_suppressions(
    files: list[Any],
    findings: list[Any],
) -> dict[str, Any]:
    """Split findings into active vs suppressed (+ expired waivers)."""
    if not isinstance(files, list):
        raise ValueError("files must be a list")
    if not isinstance(findings, list):
        raise ValueError("findings must be a list")
    directives: list[dict[str, Any]] = []
    for idx, entry in enumerate(files):
        if not isinstance(entry, dict):
            raise ValueError(f"files[{idx}]: must be an object")
        path = str(entry.get("path") or entry.get("file") or f"file{idx}")
        if "content" not in entry:
            raise ValueError(f"files[{idx}]: content required")
        directives.extend(parse_directives(path, entry["content"]))
    live = [d for d in directives if not d["expired"]]
    expired = [d for d in directives if d["expired"]]
    suppressed: list[dict[str, Any]] = []
    active: list[dict[str, Any]] = []
    for idx, raw in enumerate(findings):
        finding = _check_finding(raw, idx)
        hit = next(
            (
                d
                for d in live
                if d["file"] == finding["file"]
                and d["line"] in (finding["line"], finding["line"] - 1)
                and (not d["rules"] or finding["rule_id"].lower() in d["rules"])
            ),
            None,
        )
        if hit is None:
            active.append(finding)
        else:
            suppressed.append(
                {
                    **finding,
                    "suppressed_by": {
                        "line": hit["line"],
                        "rules": hit["rules"],
                        "owner": hit["owner"],
                        "expires": hit["expires"],
                        "reason": hit["reason"],
                    },
                }
            )
    return {
        "suppressed": suppressed,
        "suppressed_count": len(suppressed),
        "active": active,
        "active_count": len(active),
        "expired": expired,
        "expired_count": len(expired),
        "directives": len(directives),
    }


def parse_bundle(bundle: str) -> list[dict[str, str]]:
    """Split `=== path ===` blocks into [{path, content}]."""
    files: list[dict[str, str]] = []
    path: str | None = None
    buf: list[str] = []
    for line in (bundle or "").splitlines():
        m = re.match(r"^===\s*(.+?)\s*===$", line.strip())
        if m:
            if path is not None:
                files.append({"path": path, "content": "\n".join(buf)})
            path = m.group(1)
            buf = []
        elif path is not None:
            buf.append(line)
    if path is not None:
        files.append({"path": path, "content": "\n".join(buf)})
    return files


def sandbox_result() -> dict[str, Any]:
    """Canned match: one suppressed (owned), one active, one expired."""
    return {
        "suppressed": [
            {
                "rule_id": "sast-exec-shell",
                "name": "Shell injection",
                "severity": "high",
                "cwe": "CWE-78",
                "file": "app.py",
                "line": 42,
                "suppressed_by": {
                    "line": 41,
                    "rules": ["sast-exec-shell"],
                    "owner": "ops",
                    "expires": "2099-01-01",
                    "reason": "lab-only runner",
                },
            }
        ],
        "suppressed_count": 1,
        "active": [
            {
                "rule_id": "sast-sql-string",
                "name": "SQL concat",
                "severity": "high",
                "cwe": "CWE-89",
                "file": "app.py",
                "line": 15,
            }
        ],
        "active_count": 1,
        "expired": [
            {
                "file": "old.py",
                "line": 7,
                "rules": [],
                "owner": "ops",
                "expires": "2020-01-01",
                "reason": "stale waiver",
                "expired": True,
            }
        ],
        "expired_count": 1,
        "directives": 2,
        "sandbox": True,
    }
