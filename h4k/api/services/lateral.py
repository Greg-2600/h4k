# Lateral movement and network pivot module.
# ARP/route discovery, tunnel setup (SSH SOCKS / chisel), and SMB session
# establishment. Discovery is read-only; tunnel/relay helpers establish a
# connection and are only invoked explicitly against authorized hosts.
import logging
import os
import socket
import struct
import subprocess  # nosec B404 - launches fixed-argv tunneling tools
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.lateral")

COMMON_PORTS = (22, 80, 443, 445, 139, 3389, 5985, 5986, 8080, 8443, 11434, 18799)


class LateralMovement:
    """Network pivot and lateral movement helpers."""

    def __init__(
        self,
        msf_client: Any = None,
        progress: Callable[[str, float], None] | None = None,
    ) -> None:
        self.msf = msf_client
        self.progress = progress or (lambda msg, pct: None)
        self.tunnels: list[dict[str, Any]] = []

    def discover_network(self, cidr: str = "192.168.1.0/24") -> dict[str, Any]:
        """Read-only network discovery (host liveness is not probed here)."""
        self.progress(f"discovering network {cidr}", 10)
        routes = self._get_routes()
        self.progress(f"mapped {len(routes)} routes", 50)
        return {
            "cidr": cidr,
            "hosts": [],
            "routes": routes,
            "services": {},
            "local_ips": self._get_local_ips(),
            "note": "host/service enumeration is left to nmap; this maps local "
            "interfaces and routes only",
        }

    def _get_routes(self) -> list[dict[str, Any]]:
        routes: list[dict[str, Any]] = []
        try:
            with open("/proc/net/route", encoding="utf-8") as fh:
                for line in fh.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 8:
                        routes.append(
                            {
                                "interface": parts[0],
                                "destination": self._hex_to_ip(parts[1]),
                                "gateway": self._hex_to_ip(parts[2]),
                                "flags": parts[3],
                                "mask": self._hex_to_ip(parts[7]),
                            }
                        )
        except OSError as exc:  # pragma: no cover - defensive
            logger.debug("route read failed: %s", exc)
        return routes

    @staticmethod
    def _hex_to_ip(hex_str: str) -> str:
        """Decode a /proc/net/route address (little-endian 32-bit hex)."""
        try:
            return socket.inet_ntoa(struct.pack("<I", int(hex_str, 16)))
        except (ValueError, OSError, struct.error):
            return "0.0.0.0"  # nosec B104 - fallback address string, not a bind

    @staticmethod
    def _get_local_ips() -> list[str]:
        """Return the local source IP (the UDP connect trick picks one route)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.connect(("8.8.8.8", 80))
                return [sock.getsockname()[0]]
            finally:
                sock.close()
        except OSError:
            return []

    def create_ssh_tunnel(
        self,
        target: str,
        username: str,
        password: str | None = None,
        key_path: str | None = None,
        local_port: int = 1080,
    ) -> dict[str, Any]:
        """Create an SSH dynamic tunnel (SOCKS proxy)."""
        cmd = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "-D",
            str(local_port),
            "-N",
            "-f",
        ]
        if key_path:
            cmd += ["-i", key_path]
        else:
            cmd += ["-o", "PreferredAuthentications=password"]
        cmd.append(f"{username}@{target}")

        env = dict(os.environ)
        if password:
            env["SSHPASS"] = password
            cmd = ["sshpass", "-e", *cmd]

        try:
            proc = subprocess.Popen(  # nosec B603 - fixed argv, no shell
                cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        except FileNotFoundError as exc:
            return {"success": False, "reason": str(exc)}
        self.tunnels.append(
            {
                "type": "ssh_socks",
                "target": target,
                "local_port": local_port,
                "pid": proc.pid,
            }
        )
        return {"success": True, "local_port": local_port, "pid": proc.pid}

    def create_chisel_tunnel(
        self,
        target: str,
        remote_port: int = 8080,
        local_port: int = 8080,
        reverse: bool = True,
    ) -> dict[str, Any]:
        """Create a chisel reverse/forward tunnel for pivoting."""
        if reverse:
            cmd = [
                "chisel",
                "client",
                target,
                f"R:{local_port}:127.0.0.1:{remote_port}",
            ]
        else:
            cmd = ["chisel", "server", "-p", str(local_port), "--reverse"]
        try:
            proc = subprocess.Popen(  # nosec B603 - fixed argv, no shell
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        except FileNotFoundError:
            return {"success": False, "reason": "chisel not installed"}
        self.tunnels.append(
            {
                "type": "chisel",
                "target": target,
                "local_port": local_port,
                "remote_port": remote_port,
                "pid": proc.pid,
            }
        )
        return {"success": True, "local_port": local_port, "pid": proc.pid}

    def relay_smb(
        self, target: str, username: str, password: str, domain: str = ""
    ) -> dict[str, Any]:
        """Establish an authenticated SMB session via impacket."""
        try:
            from impacket.smbconnection import SMBConnection

            conn = SMBConnection(target, target)
            conn.login(username, password, domain)
            conn.close()
            return {"success": True, "message": f"SMB session established on {target}"}
        except ImportError:
            return {"success": False, "reason": "impacket not available"}
        except Exception as exc:
            return {"success": False, "reason": str(exc)}

    def scan_through_tunnel(
        self,
        proxy: str,
        targets: list[str],
        ports: list[int] | None = None,
    ) -> dict[str, Any]:
        """TCP-connect scan of targets, optionally through a SOCKS5 proxy."""
        ports = ports or [22, 80, 443, 445, 3389, 8080, 8443]
        results: dict[str, list[int]] = {}
        for target in targets:
            open_ports = [port for port in ports if self._tcp_open(proxy, target, port)]
            if open_ports:
                results[target] = open_ports
        return {"scanned": len(targets), "results": results}

    @staticmethod
    def _tcp_open(proxy: str, target: str, port: int) -> bool:
        sock: Any = None
        try:
            if "socks" in proxy:
                import socks  # type: ignore[import-untyped]

                sock = socks.socksocket()
                sock.set_proxy(socks.SOCKS5, "127.0.0.1", int(proxy.rsplit(":", 1)[-1]))
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            return sock.connect_ex((target, port)) == 0
        except Exception:
            return False
        finally:
            if sock is not None:
                sock.close()

    def close_all_tunnels(self) -> None:
        for tunnel in self.tunnels:
            try:
                os.kill(tunnel["pid"], 9)
            except OSError:
                continue
        self.tunnels.clear()
