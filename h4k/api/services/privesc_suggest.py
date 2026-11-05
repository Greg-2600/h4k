"""Privesc suggester — linPEAS/winPEAS-style checklist (Backlog #27).

`host_privesc_audit` (services/privesc.py) already proves specific
vectors. This module is the operator's checklist *around* it: ten
read-only checks every low-priv shell should run, each returning
pass/fail/info plus the exact finding and a fix hint. Nothing here
needs a password, writes a file, or runs a payload — `id`, `ls` and
bounded `find` only. Sandbox returns a canned checklist.
"""

from __future__ import annotations

import logging
import os
import subprocess  # nosec B404 - fixed-argv read-only probes
from typing import Any

logger = logging.getLogger("h4k.privesc_suggest")

_DANGEROUS_SUID = {
    "nmap",
    "vim",
    "vi",
    "less",
    "more",
    "find",
    "bash",
    "sh",
    "dash",
    "awk",
    "perl",
    "python",
    "python3",
    "ruby",
    "php",
    "lua",
    "gdb",
    "capsh",
    "env",
    "man",
    "wget",
    "curl",
    "scp",
    "rsync",
    "tar",
    "zip",
}


def _run(argv: list[str], timeout: int = 15) -> tuple[int | None, str, str]:
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    except FileNotFoundError as exc:
        return -1, "", f"{exc.filename} not installed"
    except Exception as exc:  # pragma: no cover - defensive
        return -1, "", str(exc)


def check_kernel() -> dict[str, Any]:
    rc, out, _ = _run(["uname", "-r"], timeout=5)
    version = out.strip().split()[0] if rc == 0 else ""
    return {
        "id": "kernel",
        "title": "Kernel version",
        "status": "info" if version else "fail",
        "detail": version or "uname unavailable",
        "fix": "compare against your distro's supported kernels; old trees miss mitigations",
    }


def check_suid(timeout: int = 30) -> dict[str, Any]:
    rc, out, err = _run(
        ["find", "/", "-perm", "-4000", "-type", "f"],
        timeout=timeout,  # nosec B607 - fixed argv
    )
    if rc not in (0, 1):
        return {
            "id": "suid",
            "title": "SUID binaries",
            "status": "fail",
            "detail": err.strip()[:200] or "find failed",
            "fix": "enumerate SUID binaries when find becomes available",
        }
    bins = sorted(
        {line.rsplit("/", 1)[-1] for line in out.splitlines() if line.strip()}
    )
    hot = sorted(set(bins) & _DANGEROUS_SUID)
    return {
        "id": "suid",
        "title": "SUID binaries",
        "status": "fail" if hot else "pass",
        "detail": f"{len(bins)} SUID binaries"
        + (f"; GTFOBins: {', '.join(hot)}" if hot else "; no GTFOBins hits"),
        "fix": (
            "remove the SUID bit or the binary if the GTFOBins entry is reachable"
            if hot
            else ""
        ),
    }


def check_capabilities() -> dict[str, Any]:
    rc, out, err = _run(["getcap", "-r", "/"], timeout=30)  # nosec B607 - fixed argv
    if rc not in (0, 1):
        return {
            "id": "caps",
            "title": "File capabilities",
            "status": "fail",
            "detail": err.strip()[:200] or "getcap failed",
            "fix": "enumerate file capabilities when getcap is available",
        }
    lines = [line for line in out.splitlines() if "=" in line][:20]
    hot = [line for line in lines if "cap_dac" in line or "cap_setuid" in line]
    return {
        "id": "caps",
        "title": "File capabilities",
        "status": "fail" if hot else "pass",
        "detail": (
            "; ".join(hot) if hot else f"{len(lines)} capped files, none DAC-bypassing"
        ),
        "fix": "drop cap_dac_read_search/cap_setuid or the binary" if hot else "",
    }


def check_sudo() -> dict[str, Any]:
    rc, out, _err = _run(["sudo", "--version"], timeout=5)
    if rc != 0:
        return {
            "id": "sudo",
            "title": "sudo version",
            "status": "info",
            "detail": "sudo not present",
            "fix": "",
        }
    first = out.strip().splitlines()[0] if out.strip() else ""
    return {
        "id": "sudo",
        "title": "sudo version",
        "status": "info",
        "detail": first[:120] or "sudo present",
        "fix": "cross-check against CVE-2019-14287/CVE-2021-3156 ranges for this build",
    }


def check_path_writable() -> dict[str, Any]:
    writable = [
        p
        for p in os.environ.get("PATH", "").split(":")
        if p and os.path.isdir(p) and os.access(p, os.W_OK)
    ]
    return {
        "id": "path",
        "title": "Writable PATH dirs",
        "status": "fail" if writable else "pass",
        "detail": (
            f"writable: {', '.join(writable)}" if writable else "no writable PATH dirs"
        ),
        "fix": (
            "remove group/other write permission from PATH directories"
            if writable
            else ""
        ),
    }


def check_cron() -> dict[str, Any]:
    import glob as _glob

    targets = [
        "/etc/crontab",
        "/etc/cron.d",
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
    ]
    writable = [
        t
        for t in targets
        for t in ([t] if os.path.isfile(t) else _glob.glob(t + "/*"))
        if os.access(t, os.W_OK)
    ]
    return {
        "id": "cron",
        "title": "Writable cron files",
        "status": "fail" if writable else "pass",
        "detail": (
            f"writable: {', '.join(writable[:10])}"
            if writable
            else "no writable cron files found"
        ),
        "fix": (
            "root-owned cron with a writable script runs attacker code on schedule"
            if writable
            else ""
        ),
    }


def check_nfs() -> dict[str, Any]:
    try:
        with open("/etc/exports", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except OSError:
        return {
            "id": "nfs",
            "title": "NFS exports",
            "status": "pass",
            "detail": "no /etc/exports",
            "fix": "",
        }
    risky = [
        line.strip()
        for line in content.splitlines()
        if line.strip()
        and not line.strip().startswith("#")
        and "no_root_squash" in line
    ]
    return {
        "id": "nfs",
        "title": "NFS exports",
        "status": "fail" if risky else "pass",
        "detail": "; ".join(risky)[:300] if risky else "no no_root_squash exports",
        "fix": "replace no_root_squash with root_squash" if risky else "",
    }


def check_groups() -> dict[str, Any]:
    rc, out, _ = _run(["id", "-Gn"], timeout=5)
    groups = out.strip().split() if rc == 0 else []
    hot = sorted(set(groups) & {"docker", "lxd", "lxc", "disk", "adm", "sudo", "wheel"})
    return {
        "id": "groups",
        "title": "Supplemental groups",
        "status": "fail" if hot else ("pass" if groups else "info"),
        "detail": f"member of: {', '.join(groups) or '?'}"
        + (f" — pivot groups: {', '.join(hot)}" if hot else ""),
        "fix": (
            "docker/lxd group membership is a host-root path; disk/adm read raw devices"
            if hot
            else ""
        ),
    }


def check_shadow() -> dict[str, Any]:
    readable = os.access("/etc/shadow", os.R_OK)
    return {
        "id": "shadow",
        "title": "/etc/shadow readability",
        "status": "fail" if readable else "pass",
        "detail": "shadow readable by this user" if readable else "shadow not readable",
        "fix": "shadow must be 640 root:shadow at most" if readable else "",
    }


def check_modules() -> dict[str, Any]:
    rc, out, _ = _run(["lsmod"], timeout=10)
    if rc != 0:
        return {
            "id": "modules",
            "title": "Loaded kernel modules",
            "status": "info",
            "detail": "lsmod unavailable",
            "fix": "",
        }
    names = [line.split()[0] for line in out.splitlines()[1:] if line.split()]
    return {
        "id": "modules",
        "title": "Loaded kernel modules",
        "status": "info",
        "detail": f"{len(names)} modules loaded",
        "fix": "",
    }


def suggest() -> dict[str, Any]:
    """Run the whole read-only checklist."""
    checks = [
        check_kernel(),
        check_suid(),
        check_capabilities(),
        check_sudo(),
        check_path_writable(),
        check_cron(),
        check_nfs(),
        check_groups(),
        check_shadow(),
        check_modules(),
    ]
    fails = sum(1 for c in checks if c["status"] == "fail")
    return {"checks": checks, "count": len(checks), "fails": fails}


def sandbox_suggest() -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    return {
        "checks": [
            {
                "id": "kernel",
                "title": "Kernel version",
                "status": "info",
                "detail": "Linux 3.10 (sandbox)",
                "fix": "",
            },
            {
                "id": "suid",
                "title": "SUID binaries",
                "status": "fail",
                "detail": "2 SUID binaries; GTFOBins: find",
                "fix": "remove the SUID bit or the binary if the GTFOBins entry is reachable",
            },
            {
                "id": "groups",
                "title": "Supplemental groups",
                "status": "fail",
                "detail": "member of: lab docker — pivot groups: docker",
                "fix": "docker/lxd group membership is a host-root path; disk/adm read raw devices",
            },
            {
                "id": "shadow",
                "title": "/etc/shadow readability",
                "status": "pass",
                "detail": "shadow not readable",
                "fix": "",
            },
        ],
        "count": 4,
        "fails": 2,
        "sandbox": True,
    }
