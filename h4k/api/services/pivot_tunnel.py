"""Chisel/sshuttle pivot — one-click tunnel + proxied rescan (Backlog #34).

Opening a tunnel is half the job; the other half is scanning *through*
it. This module starts an SSH dynamic-forward (`-D`, SOCKS) or a chisel
server as a supervised background process, tracks it in a registry, and
re-scans a target through the proxy with a stdlib SOCKS5 client (no new
dependencies) plus a banner grab per open port.

Every step is explicit and lab-scoped: tunnels bind loopback only, the
proxied scan touches only the operator-supplied target, and stopping a
tunnel kills its process. Sandbox returns canned tunnels and findings.
"""

from __future__ import annotations

import json
import logging
import socket
import struct
import subprocess  # nosec B404 - fixed-argv tunnel helpers
import time
from pathlib import Path
from typing import Any

from paths import data_dir

logger = logging.getLogger("h4k.pivot_tunnel")

REGISTRY = "pivot_tunnels.json"


def _registry_path() -> Path:
    path = data_dir() / REGISTRY
    return path


def _load() -> dict[str, Any]:
    try:
        return json.loads(_registry_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"tunnels": {}}


def _save(state: dict[str, Any]) -> None:
    path = _registry_path()
    try:
        path.write_text(json.dumps(state, indent=1), encoding="utf-8")
    except OSError as exc:
        logger.debug("tunnel registry unwritable: %s", exc)


def _alive(pid: int) -> bool:
    try:
        import os

        os.kill(pid, 0)
        return True
    except (OSError, ValueError, OverflowError):
        return False


def list_tunnels() -> dict[str, Any]:
    """Tracked tunnels, with liveness re-checked."""
    state = _load()
    out = []
    for tid, t in state.get("tunnels", {}).items():
        alive = _alive(int(t.get("pid", -1)))
        out.append({**t, "id": tid, "alive": alive})
    return {"tunnels": out, "count": len(out)}


def start_tunnel(
    kind: str,
    port: int = 0,
    target: str = "",
    ssh_host: str = "",
    ssh_user: str = "",
    ssh_port: int = 22,
) -> dict[str, Any]:
    """Start a loopback-bound tunnel; kind is `ssh` (-D) or `chisel` server."""
    kind = (kind or "").strip().lower()
    if kind not in ("ssh", "chisel"):
        raise ValueError("kind must be ssh or chisel")
    if kind == "ssh" and not (ssh_host and ssh_user):
        raise ValueError("ssh tunnels need ssh_host and ssh_user")
    listen_arg = f"127.0.0.1:{port or 0}" if kind == "ssh" else str(port or 0)
    if kind == "ssh":
        argv = [
            "ssh",
            "-N",
            "-D",
            listen_arg,
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "BatchMode=yes",
            "-p",
            str(ssh_port),
            f"{ssh_user}@{ssh_host}",
        ]
    else:
        argv = [
            "chisel",
            "server",
            "-p",
            str(port or 0),
            "--host",
            "127.0.0.1",
            "--reverse",
        ]
    try:
        proc = subprocess.Popen(  # nosec B603 - fixed argv, no shell
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        return {"success": False, "error": f"{exc.filename} not installed"}
    except Exception as exc:
        return {"success": False, "error": str(exc)[:200]}
    time.sleep(0.5)
    listen = listen_arg
    tid = f"{kind}-{proc.pid}"
    state = _load()
    state.setdefault("tunnels", {})[tid] = {
        "kind": kind,
        "pid": proc.pid,
        "listen": str(listen),
        "target": target,
        "ssh_host": ssh_host,
    }
    _save(state)
    return {
        "success": True,
        "id": tid,
        "pid": proc.pid,
        "listen": str(listen),
        "kind": kind,
        "alive": _alive(proc.pid),
    }


def stop_tunnel(tunnel_id: str) -> dict[str, Any]:
    """Kill a tracked tunnel process and forget it."""
    import os
    import signal

    state = _load()
    entry = (state.get("tunnels") or {}).pop(str(tunnel_id), None)
    _save(state)
    if not entry:
        return {"stopped": False, "error": "unknown tunnel"}
    try:
        os.kill(int(entry.get("pid", -1)), signal.SIGTERM)
        return {"stopped": True, "id": tunnel_id}
    except (OSError, ValueError) as exc:
        return {"stopped": True, "id": tunnel_id, "note": f"already gone: {exc}"}


def socks_connect(
    proxy_host: str, proxy_port: int, target: str, port: int, timeout: float = 8.0
) -> socket.socket:
    """Open a TCP stream to target:port through a SOCKS5 proxy (no auth)."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        if sock.recv(2) != b"\x05\x00":
            raise OSError("SOCKS5 handshake rejected")
        req = b"\x05\x01\x00\x01" + socket.inet_aton(target) + struct.pack(">H", port)
        sock.sendall(req)
        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != 0x00:
            raise OSError(
                f"SOCKS5 CONNECT failed (rep={resp[1] if len(resp) > 1 else '?'})"
            )
        return sock
    except Exception:
        sock.close()
        raise


def proxied_scan(
    proxy_host: str,
    proxy_port: int,
    target: str,
    ports: list[int] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """TCP connect scan + banner grab through a SOCKS proxy."""
    results: list[dict[str, Any]] = []
    for port in ports or [22, 80, 443, 445, 3389, 8080, 8443]:
        started = time.time()
        try:
            sock = socks_connect(
                proxy_host, proxy_port, target, int(port), timeout=timeout
            )
            try:
                sock.settimeout(3.0)
                try:
                    raw_lines = (
                        sock.recv(512)
                        .decode("utf-8", errors="replace")
                        .strip()
                        .splitlines()
                    )
                    banner = raw_lines[0][:200] if raw_lines else ""
                except OSError:
                    banner = ""
            finally:
                sock.close()
            results.append(
                {
                    "port": port,
                    "open": True,
                    "banner": banner,
                    "elapsed": round(time.time() - started, 2),
                }
            )
        except (OSError, ValueError, struct.error) as exc:
            results.append({"port": port, "open": False, "error": str(exc)[:120]})
    open_ports = [r for r in results if r["open"]]
    return {
        "target": target,
        "proxy": f"{proxy_host}:{proxy_port}",
        "results": results,
        "open": open_ports,
        "open_count": len(open_ports),
    }


def sandbox_tunnels() -> dict[str, Any]:
    return {
        "tunnels": [
            {
                "id": "ssh-4242",
                "kind": "ssh",
                "pid": 4242,
                "listen": "127.0.0.1:1080",
                "alive": True,
                "sandbox": True,
            }
        ],
        "count": 1,
        "sandbox": True,
    }


def sandbox_scan(target: str) -> dict[str, Any]:
    return {
        "target": target,
        "proxy": "127.0.0.1:1080",
        "results": [
            {
                "port": 22,
                "open": True,
                "banner": "SSH-2.0-OpenSSH (sandbox)",
                "elapsed": 0.01,
            },
            {"port": 80, "open": True, "banner": "Apache (sandbox)", "elapsed": 0.01},
            {"port": 443, "open": False, "error": "connection refused (sandbox)"},
        ],
        "open": [{"port": 22}, {"port": 80}],
        "open_count": 2,
        "sandbox": True,
    }
