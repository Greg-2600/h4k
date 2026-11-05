"""LLMNR/NBT-NS poison lab (Backlog #9).

`/api/ad/responder` runs real poisoning on any interface it is given.
This module is the safe lab counterpart: a passive listener + capture
parser by default (Responder analyze mode, `-A` — answers nothing), with
actual poisoning gated behind *two* explicit checks:

1. the operator passes `poison=True` **and** `confirm_lab=True`, and
2. the interface looks like a lab/container NIC
   (`lo`, `docker*`, `br-*`, `veth*`, `virbr*`) or the operator set the
   `H4K_POISONLAB_ALLOW=all` escape hatch.

Anything else is refused with a 400 and a reason — poisoning never fires
by accident, and the sandbox stand-in never touches a socket.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess  # nosec B404 - fixed-argv responder wrapper
from collections.abc import Callable
from fnmatch import fnmatch
from typing import Any

logger = logging.getLogger("h4k.poison_lab")

RESPONDER = "responder"
ALLOW_ENV = "H4K_POISONLAB_ALLOW"
LAB_PATTERNS = ("lo", "docker*", "br-*", "veth*", "virbr*", "lxcbr*")

_NTLM_RE = re.compile(r"NTLMv1-SSP\s+Hash\s*:\s*(\S+)|NTLMv2-SSP\s+Hash\s*:\s*(\S+)")


def is_lab_interface(interface: str) -> bool:
    """True when the NIC name looks like a lab/container interface."""
    name = (interface or "").strip()
    if os.environ.get(ALLOW_ENV, "").strip().lower() == "all":
        return True
    return any(fnmatch(name, pat) for pat in LAB_PATTERNS)


def extract_hashes(text: str) -> list[str]:
    """Pull captured NTLM challenge/response hashes out of Responder logs."""
    seen: list[str] = []
    for m in _NTLM_RE.finditer(text or ""):
        h = (m.group(1) or m.group(2) or "").strip()
        if h and "::" in h and h not in seen:
            seen.append(h)
    return seen


class PoisonLab:
    """Passive listener first, poisoning only with both confirmations."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)

    def _run(self, argv: list[str], timeout: int = 300) -> dict[str, Any]:
        self.progress(f"[poisonlab] {' '.join(argv[:6])}...", 0)
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

    def listen(
        self,
        interface: str,
        duration: int = 120,
        poison: bool = False,
        confirm_lab: bool = False,
    ) -> dict[str, Any]:
        """Listen on one interface. Poisoning needs both confirmations."""
        iface = (interface or "").strip()
        if not iface:
            return {"error": "interface required", "refused": True}
        if poison:
            if not confirm_lab:
                return {
                    "error": "refused: poisoning needs confirm_lab=true",
                    "refused": True,
                    "interface": iface,
                }
            if not is_lab_interface(iface):
                return {
                    "error": f"refused: {iface} is not a lab/container interface"
                    f" (set {ALLOW_ENV}=all to override)",
                    "refused": True,
                    "interface": iface,
                }
            argv = [RESPONDER, "-I", iface]
        else:
            argv = [RESPONDER, "-I", iface, "-A"]
        result = self._run(argv, timeout=max(10, duration + 30))
        hashes = extract_hashes(result.get("stdout", ""))
        return {
            **result,
            "interface": iface,
            "mode": "poison" if poison else "analyze",
            "hashes": hashes,
            "hash_count": len(hashes),
        }


def sandbox_listen(interface: str) -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    log = (
        "[*] [LLMNR] Poisoned answer sent to 10.10.10.9\n"
        "NTLMv2-SSP Hash     : alice::LAB:1122334455667788:"
        "aabbccddeeff00112233445566778899:"
        "00112233445566778899aabbccddeeff00"
    )
    return {
        "stdout": log,
        "stderr": "",
        "rc": 0,
        "success": True,
        "timed_out": False,
        "interface": interface or "lo",
        "mode": "analyze",
        "hashes": extract_hashes(log),
        "hash_count": 1,
        "sandbox": True,
    }


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data
