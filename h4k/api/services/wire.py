# Small, dependency-free wire helpers shared by the lab traffic kit and the
# IoT/OT probe pack.
#
# Everything here is deliberately bounded: connect/read timeouts, a hard cap on
# how many bytes are kept, and a target policy that refuses public addresses
# unless the operator explicitly opts in. These are probes, not exploits — the
# callers only send read-only requests.
import contextlib
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Any

from services import noise

MAX_BYTES = 8192


@dataclass(frozen=True)
class Target:
    host: str
    port: int

    def key(self) -> str:
        return f"{self.host}:{self.port}"


def parse_target(value: str, default_port: int = 80) -> Target:
    raw = (value or "").strip()
    if not raw:
        raise ValueError("target is required")
    if raw.startswith("["):
        host, sep, rest = raw[1:].partition("]")
        if not sep:
            raise ValueError(f"malformed IPv6 target: {raw}")
        port = (
            int(rest[1:])
            if rest.startswith(":") and rest[1:].isdigit()
            else default_port
        )
        return Target(host, port)
    if raw.count(":") == 1 and raw.rsplit(":", 1)[1].isdigit():
        host_text, port_text = raw.rsplit(":", 1)
        return Target(host_text.strip("[]"), int(port_text))
    return Target(raw, default_port)


def resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve {host}: {exc}") from exc
    seen: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


def is_lab_address(address: str) -> bool:
    """True for loopback, RFC1918, link-local and other non-public ranges."""
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return False
    return bool(
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def check_lab_target(host: str, *, allow_public: bool = False) -> list[str]:
    """Resolve and enforce the lab-only target policy.

    Returns the resolved addresses so callers can log exactly what was touched.
    A hostname is allowed only if *every* address it resolves to is non-public;
    a split-horizon name that points at a public address should not slip through.
    """
    addresses = resolve_host(host)
    if not allow_public:
        public = [a for a in addresses if not is_lab_address(a)]
        if public:
            raise ValueError(
                f"{host} resolves to public address(es) {', '.join(public)}; "
                "pass allow_public=true only for a host you own"
            )
    return addresses


def _read_bounded(sock: socket.socket, limit: int = MAX_BYTES) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        try:
            chunk = sock.recv(min(4096, limit - total))
        except TimeoutError:
            break
        except OSError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def tcp_exchange(
    host: str,
    port: int,
    payload: bytes = b"",
    *,
    timeout: float = 3.0,
    read: bool = True,
    tls: bool = False,
    server_name: str | None = None,
) -> dict[str, Any]:
    """One bounded TCP (or TLS) exchange. Never raises for network errors."""
    started = time.monotonic()
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "transport": "tls" if tls else "tcp",
        "sent": len(payload),
        "received": 0,
        "banner": "",
        "ok": False,
        "error": "",
        "duration_ms": 0,
    }
    try:
        permit = noise.acquire(host)
    except TimeoutError as exc:
        result["error"] = f"noise governor: {exc}"
        return result
    status_code = 0
    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=server_name or host)
        if payload:
            sock.sendall(payload)
        data = _read_bounded(sock) if read else b""
        result["received"] = len(data)
        result["banner"] = data[:1024].decode("utf-8", errors="replace")
        result["raw_hex"] = data[:256].hex()
        result["ok"] = True
        if data.startswith(b"HTTP/"):
            try:
                status_code = int(data.split(b" ", 2)[1])
            except (IndexError, ValueError):
                status_code = 0
    except (OSError, ssl.SSLError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            with contextlib.suppress(OSError):
                sock.close()
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        noise.release(permit, status_code=status_code)
    return result


def udp_exchange(
    host: str,
    port: int,
    payload: bytes,
    *,
    timeout: float = 3.0,
    expect_reply: bool = True,
) -> dict[str, Any]:
    """One bounded UDP exchange, for DNS/CoAP/SSDP/BACnet/SNMP probes."""
    started = time.monotonic()
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "transport": "udp",
        "sent": len(payload),
        "received": 0,
        "response": "",
        "raw_hex": "",
        "ok": False,
        "error": "",
        "duration_ms": 0,
    }
    try:
        permit = noise.acquire(host)
    except TimeoutError as exc:
        result["error"] = f"noise governor: {exc}"
        return result
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(payload, (host, port))
            if expect_reply:
                data, _addr = sock.recvfrom(MAX_BYTES)
                result["received"] = len(data)
                result["response"] = data[:1024].decode("utf-8", errors="replace")
                result["raw_hex"] = data[:256].hex()
                result["raw"] = data
            result["ok"] = True
    except (TimeoutError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        noise.release(permit)
    return result


def http_get(
    host: str,
    port: int,
    path: str = "/",
    *,
    timeout: float = 3.0,
    host_header: str | None = None,
    user_agent: str = "h4k-lab-traffic/1.0",
    tls: bool = False,
) -> dict[str, Any]:
    header = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header or host}\r\n"
        f"User-Agent: {user_agent}\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    ).encode()
    result = tcp_exchange(host, port, header, timeout=timeout, tls=tls)
    banner = result.get("banner", "")
    status = ""
    if banner.startswith("HTTP/"):
        parts = banner.split("\r\n", 1)[0].split()
        status = " ".join(parts[1:3])
    result["status"] = status
    result["body_preview"] = banner.split("\r\n\r\n", 1)[-1][:512]
    return result
