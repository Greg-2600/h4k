"""Docker socket guard — detect + policy suggestion (Backlog #38).

Read-only inspection of the machine the API runs on: well-known socket
paths are stat'ed (socket? world-writable?), the operator's `docker`
group membership is checked (root-equivalent), and an insecure
`DOCKER_HOST=tcp://…` env is flagged. Every finding ships a concrete
hardening policy — remove the mount, proxy the socket, drop the group.

The `host` parameter only labels the engagement ledger entry (detection
always inspects the local runtime); ledgering is scope-enforced.
Sandbox returns canned findings without touching the filesystem.
"""

from __future__ import annotations

import grp
import logging
import os
import stat
from typing import Any

logger = logging.getLogger("h4k.docker_guard")

SOCKET_PATHS: tuple[str, ...] = (
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/var/run/containerd/containerd.sock",
    "/run/containerd/containerd.sock",
    "/var/run/podman/podman.sock",
)

_POLICIES: dict[str, str] = {
    "socket-mounted": (
        "Remove the socket mount (`-v /var/run/docker.sock:…`) from the "
        "container; if the workload needs Docker reads, front the socket "
        "with a filtering proxy (least-privilege ACL) instead of bind-mounting it."
    ),
    "socket-world-writable": (
        "Tighten the socket to `root:docker 0660`; a world-writable daemon "
        "socket is root for any local uid."
    ),
    "docker-group": (
        "Drop the operator from the `docker` group — group membership is "
        "root-equivalent (`docker run -v /:/host`). Use rootless Docker or "
        "sudo-scoped workflows instead."
    ),
    "docker-host-tcp": (
        "Do not point DOCKER_HOST at an unauthenticated `tcp://` daemon; "
        "bind the daemon to a unix socket or protect TCP with mutual TLS."
    ),
}


def _inspect_socket(path: str) -> dict[str, Any]:
    """Stat one well-known path; never opens or connects."""
    try:
        st = os.stat(path)
    except OSError:
        return {"path": path, "present": False}
    mode = st.st_mode
    return {
        "path": path,
        "present": True,
        "is_socket": stat.S_ISSOCK(mode),
        "world_writable": bool(mode & stat.S_IWOTH),
        "uid": st.st_uid,
        "gid": st.st_gid,
    }


def _docker_group_member() -> tuple[bool, str]:
    """True when the current user is in the local `docker` group."""
    try:
        entry = grp.getgrnam("docker")
    except KeyError:
        return False, "no local docker group"
    try:
        me = os.getlogin()
    except OSError:
        import getpass

        me = getpass.getuser()
    members = list(entry.gr_mem)
    try:
        import pwd

        primary = pwd.getpwnam(me).pw_gid == entry.gr_gid
    except (KeyError, OSError):
        primary = False
    if me in members or primary:
        return True, f"{me} in docker group (gid {entry.gr_gid})"
    return False, f"docker group exists (gid {entry.gr_gid}), {me} not a member"


def detect() -> dict[str, Any]:
    """Run the read-only checklist against the local runtime."""
    sockets = [_inspect_socket(p) for p in SOCKET_PATHS]
    member, member_evidence = _docker_group_member()
    docker_host = (os.environ.get("DOCKER_HOST") or "").strip()
    insecure_tcp = docker_host.startswith("tcp://")

    findings: list[dict[str, Any]] = []
    for sock in sockets:
        if not sock.get("present"):
            continue
        if sock.get("is_socket"):
            findings.append(
                {
                    "check": "socket-mounted",
                    "severity": "CRITICAL",
                    "title": f"container runtime socket reachable at {sock['path']}",
                    "evidence": f"{sock['path']} is a socket (uid={sock['uid']} gid={sock['gid']})",
                    "policy": _POLICIES["socket-mounted"],
                }
            )
        if sock.get("world_writable"):
            findings.append(
                {
                    "check": "socket-world-writable",
                    "severity": "CRITICAL",
                    "title": f"{sock['path']} is world-writable",
                    "evidence": f"mode has o+w on {sock['path']}",
                    "policy": _POLICIES["socket-world-writable"],
                }
            )
    if member:
        findings.append(
            {
                "check": "docker-group",
                "severity": "HIGH",
                "title": "operator holds docker-group (root-equivalent) access",
                "evidence": member_evidence,
                "policy": _POLICIES["docker-group"],
            }
        )
    if insecure_tcp:
        findings.append(
            {
                "check": "docker-host-tcp",
                "severity": "HIGH",
                "title": "DOCKER_HOST points at an unauthenticated TCP daemon",
                "evidence": f"DOCKER_HOST={docker_host}",
                "policy": _POLICIES["docker-host-tcp"],
            }
        )
    return {
        "sockets": sockets,
        "docker_group_member": member,
        "docker_group_evidence": member_evidence,
        "docker_host": docker_host,
        "findings": findings,
        "finding_count": len(findings),
        "guarded": not findings,
    }


def to_ledger(host: str, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Map guard findings to engagement vuln rows for the labeled host."""
    rows: list[dict[str, Any]] = []
    for finding in findings:
        check = str(finding.get("check") or "docker-guard").strip() or "docker-guard"
        rows.append(
            {
                "host": host,
                "name": f"docker-guard {check}",
                "severity": str(finding.get("severity") or "UNKNOWN").upper(),
                "module": "docker-guard",
                "reference": "",
                "cwe": "CWE-250",
                "detail": (
                    f"{finding.get('title', '')} evidence={finding.get('evidence', '')}"
                    f" policy={finding.get('policy', '')}"
                ).strip(),
            }
        )
    return rows


def sandbox_result() -> dict[str, Any]:
    """Canned guard result (no filesystem touched)."""
    findings = [
        {
            "check": "socket-mounted",
            "severity": "CRITICAL",
            "title": "container runtime socket reachable at /var/run/docker.sock (sandbox)",
            "evidence": "/var/run/docker.sock is a socket (sandbox)",
            "policy": _POLICIES["socket-mounted"],
        },
        {
            "check": "docker-group",
            "severity": "HIGH",
            "title": "operator holds docker-group (root-equivalent) access (sandbox)",
            "evidence": "operator in docker group (sandbox)",
            "policy": _POLICIES["docker-group"],
        },
    ]
    return {
        "sockets": [
            {
                "path": "/var/run/docker.sock",
                "present": True,
                "is_socket": True,
                "world_writable": False,
                "uid": 0,
                "gid": 0,
            }
        ],
        "docker_group_member": True,
        "docker_group_evidence": "operator in docker group (sandbox)",
        "docker_host": "",
        "findings": findings,
        "finding_count": len(findings),
        "guarded": False,
        "sandbox": True,
    }
