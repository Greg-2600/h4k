# Container-surface fuzzing: Docker Engine API, containerd gRPC framing,
# kubelet and generic HTTP (CAD-worker-style) endpoints.
#
# Detection is read-only. Fuzzing reuses the LabFuzzer mutation engine and
# crash registry; only the transport (TCP / TLS / unix-socket / gRPC frames)
# and the request templates differ. GET-only unless `allow_mutating` opts
# into POST endpoints -- even then, only fixed endpoint shapes with mutated
# values, never arbitrary method calls. Localhost daemon fuzzing can still
# kill containers (that is the point of a fuzzer); scope it to systems you
# own and prefer the read-only detect pass first.
from __future__ import annotations

import json
import logging
import socket
import ssl
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from services.fuzzer import LabFuzzer

logger = logging.getLogger("h4k.container_fuzz")

DOCKER_SOCK = "/var/run/docker.sock"
CONTAINERD_SOCK = "/run/containerd/containerd.sock"
KUBELET_PORTS = (10250, 10255)

DOCKER_GET_ENDPOINTS = (
    "/version",
    "/info",
    "/containers/json",
    "/containers/json?all=1",
    "/images/json",
    "/networks",
    "/volumes",
    "/plugins",
    "/distribution/library/alpine/json",
)
# Only ever sent when allow_mutating=True; bodies are mutated JSON, never
# operator-supplied commands.
DOCKER_POST_ENDPOINTS = (
    "/containers/create",
    "/images/create?fromImage=library/alpine",
    "/containers/prune",
)
KUBELET_GET_ENDPOINTS = (
    "/healthz",
    "/pods",
    "/runningpods",
    "/metrics",
    "/stats/summary",
    "/spec",
)

# Minimal HTTP/2 client-connection preface + SETTINGS frame; mutations flip
# bytes in the frame payload to shake the gRPC framing layer (containerd
# speaks h2c on its unix socket). This is framing fuzz, not valid RPCs.
_GRPC_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_GRPC_SETTINGS = bytes.fromhex("00000c040000000000000200000000000300000064000400100000")


def _http_api_version(sock_path: str = DOCKER_SOCK, timeout: float = 4.0) -> str | None:
    """GET /version over the Docker unix socket. None when unreachable."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sock_path)
            sock.sendall(
                b"GET /version HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            data = sock.recv(4096)
    except OSError:
        return None
    try:
        body = data.split(b"\r\n\r\n", 1)[1].decode("utf-8", "replace")
        version = json.loads(body).get("Version")
        return str(version) if version else None
    except (ValueError, IndexError, AttributeError):
        return None


def _tcp_banner(host: str, port: int, timeout: float = 3.0) -> str | None:
    """First bytes of whatever answers a TCP connect (TLS tried too)."""
    for use_tls in (False, True):
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                raw.settimeout(timeout)
                if use_tls:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(raw, server_hostname=host) as sock:
                        sock.sendall(b"GET /healthz HTTP/1.0\r\n\r\n")
                        return sock.recv(300).decode("latin1", "replace")[:200]
                raw.sendall(b"GET /healthz HTTP/1.0\r\n\r\n")
                return raw.recv(300).decode("latin1", "replace")[:200]
        except OSError:
            continue
    return None


def detect_surfaces(target: str = "127.0.0.1") -> dict[str, Any]:
    """Read-only inventory of container runtimes reachable for fuzzing."""
    surfaces: dict[str, Any] = {}
    docker_version = _http_api_version()
    surfaces["docker"] = {
        "socket": DOCKER_SOCK,
        "socket_present": Path(DOCKER_SOCK).exists(),
        "api_version": docker_version,
        "fuzzable": docker_version is not None,
    }
    surfaces["containerd"] = {
        "socket": CONTAINERD_SOCK,
        "socket_present": Path(CONTAINERD_SOCK).exists(),
        "fuzzable": Path(CONTAINERD_SOCK).exists(),
        "note": "gRPC framing fuzz only; no valid RPCs are ever sent",
    }
    kubelet: dict[str, Any] = {}
    for port in KUBELET_PORTS:
        banner = _tcp_banner(target, port)
        kubelet[str(port)] = {"open": banner is not None, "banner": banner}
    surfaces["kubelet"] = {
        "target": target,
        "ports": kubelet,
        "fuzzable": any(p["open"] for p in kubelet.values()),
    }
    return {"target": target, "surfaces": surfaces}


class ContainerSurfaceFuzzer(LabFuzzer):
    """LabFuzzer with per-surface request templates and transports.

    transports: tcp | tls | unix | grpc. grpc sends mutated HTTP/2 frames
    over the unix socket (or TCP when sock_path is None).
    """

    def __init__(
        self,
        *args: Any,
        endpoints: list[str] | None = None,
        methods: tuple[str, ...] = ("GET",),
        transport: str = "tcp",
        sock_path: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        if transport not in ("tcp", "tls", "unix", "grpc"):
            raise ValueError(f"unknown transport: {transport}")
        self.transport = transport
        self.sock_path = sock_path
        self.endpoints = endpoints or ["/"]
        self.methods = methods or ("GET",)
        self._vector_index = 0

    def _probe_http(self, url: str) -> bool:
        # The base probe speaks plaintext TCP to host:port -- wrong for unix
        # sockets and TLS ports, and a failed baseline turns every benign
        # 200 into an "anomaly". Probe the real transport instead.
        if self.transport == "unix" and self.sock_path:
            return _http_api_version(self.sock_path, timeout=self.timeout) is not None
        if self.transport == "grpc" and self.sock_path:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.connect(self.sock_path)
                return True
            except OSError:
                return False
        if self.transport == "tls":
            try:
                hostport = url.split("://", 1)[1].split("/", 1)[0]
                if ":" in hostport:
                    host, _, port_s = hostport.rpartition(":")
                    port = int(port_s or 443)
                else:
                    host, port = hostport or "127.0.0.1", 443
                _, rc, _ = self._send_tls(
                    host or "127.0.0.1", port, b"GET / HTTP/1.0\r\n\r\n"
                )
                return rc == 0
            except (ValueError, OSError):
                return False
        return super()._probe_http(url)

    def _build_vector(self, base: str, label: str, payload: bytes) -> bytes:
        slot = self._vector_index
        self._vector_index += 1
        endpoint = self.endpoints[slot % len(self.endpoints)]
        method = self.methods[(slot // max(1, len(self.endpoints))) % len(self.methods)]
        blob = payload[:512].decode("latin1", "replace")
        if self.transport == "grpc":
            frame = bytearray(_GRPC_PREFACE + _GRPC_SETTINGS + b"\x00" * 64)
            raw = payload[:64].ljust(64, b"\x00")
            frame[len(_GRPC_PREFACE + _GRPC_SETTINGS) :] = raw
            return bytes(frame)
        if method == "POST":
            body = json.dumps({"Image": "alpine", "Fuzz": blob})
            return (
                f"POST {endpoint} HTTP/1.1\r\nHost: x\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"X-Fuzz-{label}: {blob}\r\n"
                "Connection: close\r\n\r\n"
                f"{body}"
            ).encode("latin1", "replace")
        return (
            f"GET {endpoint}?_f={blob} HTTP/1.1\r\nHost: x\r\n"
            f"X-Fuzz-{label}: {blob}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("latin1", "replace")

    def _send_http(self, host: str, port: int, vector: bytes) -> tuple[str, int, float]:
        if self.transport == "unix" and self.sock_path:
            return self._send_unix(self.sock_path, vector)
        if self.transport == "tls":
            return self._send_tls(host, port, vector)
        if self.transport == "grpc":
            if self.sock_path:
                return self._send_unix(self.sock_path, vector)
            return super()._send_http(host, port, vector)
        return super()._send_http(host, port, vector)

    def _send_unix(self, path: str, vector: bytes) -> tuple[str, int, float]:
        start = time.time()
        evid, rc = "", -1
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(path)
                sock.sendall(vector)
                try:
                    data = sock.recv(2048)
                    if data:
                        rc = 0
                        evid = data[:200].decode("latin1", "replace")
                except TimeoutError:
                    rc = 2
        except FileNotFoundError:
            rc = 4
        except ConnectionResetError:
            rc = 3
        except TimeoutError:
            rc = 2
        except Exception:
            rc = -1
        return evid, rc, time.time() - start

    def _send_tls(self, host: str, port: int, vector: bytes) -> tuple[str, int, float]:
        start = time.time()
        evid, rc = "", -1
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as raw:
                raw.settimeout(self.timeout)
                with ctx.wrap_socket(raw, server_hostname=host) as sock:
                    sock.sendall(vector)
                    try:
                        data = sock.recv(2048)
                        if data:
                            rc = 0
                            evid = data[:200].decode("latin1", "replace")
                    except TimeoutError:
                        rc = 2
        except ConnectionResetError:
            rc = 3
        except ConnectionRefusedError:
            rc = 4
        except TimeoutError:
            rc = 2
        except Exception:
            rc = -1
        return evid, rc, time.time() - start


# Surface presets: (transport, default port, endpoints, mutating endpoints).
def preset(surface: str, allow_mutating: bool = False) -> dict[str, Any]:
    """Endpoint/transport preset for a named container surface."""
    if surface == "docker":
        methods: tuple[str, ...] = ("GET",)
        endpoints = list(DOCKER_GET_ENDPOINTS)
        if allow_mutating:
            methods = ("GET", "POST")
            endpoints = list(DOCKER_GET_ENDPOINTS + DOCKER_POST_ENDPOINTS)
        return {
            "transport": "unix",
            "sock_path": DOCKER_SOCK,
            "port": 2375,
            "endpoints": endpoints,
            "methods": methods,
        }
    if surface == "kubelet":
        return {
            "transport": "tls",
            "sock_path": None,
            "port": 10250,
            "endpoints": list(KUBELET_GET_ENDPOINTS),
            "methods": ("GET",),
        }
    if surface == "grpc":
        return {
            "transport": "grpc",
            "sock_path": CONTAINERD_SOCK,
            "port": 0,
            "endpoints": ["/"],
            "methods": ("GET",),
        }
    if surface == "http":
        return {
            "transport": "tcp",
            "sock_path": None,
            "port": 80,
            "endpoints": ["/"],
            "methods": ("GET", "POST") if allow_mutating else ("GET",),
        }
    raise ValueError(f"unknown surface: {surface} (docker|kubelet|grpc|http)")


def fuzz_surface(
    surface: str,
    target: str = "127.0.0.1",
    port: int | None = None,
    endpoints: list[str] | None = None,
    iterations: int = 200,
    timeout: float = 3.0,
    seed: int | None = None,
    allow_mutating: bool = False,
    progress: Callable[[str, float], None] | None = None,
) -> dict[str, Any]:
    """Run the mutation engine against one container surface (blocking)."""
    cfg = preset(surface, allow_mutating)
    if endpoints:
        cfg["endpoints"] = [e if e.startswith("/") else f"/{e}" for e in endpoints]
    if port:
        cfg["port"] = port
    fuzzer = ContainerSurfaceFuzzer(
        progress=progress,
        timeout=timeout,
        iterations=iterations,
        seed=seed,
        endpoints=cfg["endpoints"],
        methods=cfg["methods"],
        transport=cfg["transport"],
        sock_path=cfg["sock_path"],
    )
    now = datetime.now(UTC).isoformat()
    candidates = fuzzer._fuzz_http(target, cfg["port"], "http")
    return {
        "surface": surface,
        "target": target,
        "port": cfg["port"],
        "transport": cfg["transport"],
        "started": now,
        "candidates": candidates,
        "count": len(candidates),
        "stats": fuzzer.stats,
    }
