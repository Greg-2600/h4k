"""gRPC enumerator + fuzz — reflection + payload shapes (Backlog #46).

Opt-in, lab-only analysis of one gRPC endpoint YOU own, with no new
dependencies: a minimal hand-rolled HTTP/2 client covering exactly the
two calls this feature needs (server reflection
`ServerReflectionInfo` and unary framing fuzz), over cleartext h2c
prior-knowledge or TLS with ALPN `h2`.

Enumeration sends a reflection `list_services` request and
heuristically extracts dotted service names from the raw response
bytes (string scan, not a protobuf decode — stated plainly in results
as `heuristic: true`). Fuzzing replays mutated gRPC frames at one
method (oversize length prefix, truncated payload, compressed-flag
lies, empty/garbage/split/double messages, post-headers RST) and
records GOAWAY / RST_STREAM / drops / timeouts / non-zero grpc-status
as candidates. A fresh connection per iteration keeps runs isolated.

Findings ledger as engagement vulns on the target host when
`engagement_id` is given (scope-enforced). Sandbox returns canned
services and candidates without opening any socket.
"""

from __future__ import annotations

import logging
import os
import random
import re
import socket
import ssl
import struct
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.grpcfuzz")

# Frame types.
_F_DATA, _F_HEADERS, _F_RST, _F_SETTINGS, _F_GOAWAY, _F_WINDOW = 0, 1, 3, 4, 7, 8
_FLAG_END_STREAM, _FLAG_END_HEADERS, _FLAG_ACK = 0x1, 0x4, 0x1

# RFC 7541 Appendix A entries this decoder knows (indexed header fields).
_STATIC = {
    1: (":authority", ""),
    2: (":method", "GET"),
    3: (":method", "POST"),
    4: (":path", "/"),
    5: (":path", "/index.html"),
    6: (":scheme", "http"),
    7: (":scheme", "https"),
    8: (":status", "200"),
    9: (":status", "204"),
    10: (":status", "206"),
    11: (":status", "304"),
    12: (":status", "400"),
    13: (":status", "404"),
    14: (":status", "500"),
    15: ("accept-charset", ""),
    16: ("accept-encoding", "gzip, deflate"),
    17: ("accept-language", ""),
    18: ("accept-ranges", ""),
    19: ("accept", ""),
    20: ("access-control-allow-origin", ""),
    27: ("content-length", ""),
    28: ("content-type", ""),
    31: ("date", ""),
    32: ("etag", ""),
    33: ("expect", ""),
}

_NAME_RE = re.compile(rb"[A-Za-z][\w.]{2,120}")


def _enc_int(value: int, prefix_bits: int, prefix: int) -> bytes:
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([prefix | value])
    out = bytearray([prefix | limit])
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _dec_int(buf: bytes, pos: int, prefix_bits: int) -> tuple[int, int]:
    limit = (1 << prefix_bits) - 1
    value = buf[pos] & limit
    pos += 1
    if value == limit:
        shift = 0
        while True:
            byte = buf[pos]
            pos += 1
            value += (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
    return value, pos


def _hpack_literal(name: str, value: str) -> bytes:
    """Literal header field without indexing, new name, no Huffman."""
    out = bytearray([0x00])
    nb, vb = name.encode(), value.encode()
    out += _enc_int(len(nb), 7, 0x00) + nb
    out += _enc_int(len(vb), 7, 0x00) + vb
    return bytes(out)


def _hpack_decode(block: bytes) -> dict[str, str]:
    """Best-effort HPACK decode: indexed + unhuffmaned literals only."""
    headers: dict[str, str] = {}
    pos = 0
    try:
        while pos < len(block):
            byte = block[pos]
            if byte & 0x80:  # indexed
                idx, pos = _dec_int(block, pos, 7)
                if idx in _STATIC:
                    name, value = _STATIC[idx]
                    headers[name] = value
            elif byte & 0x40:  # literal with incremental indexing
                idx, pos = _dec_int(block, pos, 6)
                name = ""
                if idx == 0:
                    nlen, pos = _dec_int(block, pos, 7)
                    if block[pos - (nlen.bit_length() or 0) - 1] & 0x80:
                        return headers  # Huffman — bail on this block
                    name = block[pos : pos + nlen].decode("latin1")
                    pos += nlen
                elif idx in _STATIC:
                    name = _STATIC[idx][0]
                else:
                    return headers
                vlen, pos = _dec_int(block, pos, 7)
                value = block[pos : pos + vlen].decode("latin1")
                pos += vlen
                if name:
                    headers[name] = value
            elif (byte & 0xF0) == 0x00:  # literal without indexing
                idx, pos = _dec_int(block, pos, 4)
                name = ""
                if idx == 0:
                    nlen, pos = _dec_int(block, pos, 7)
                    name = block[pos : pos + nlen].decode("latin1")
                    pos += nlen
                elif idx in _STATIC:
                    name = _STATIC[idx][0]
                else:
                    return headers
                vlen, pos = _dec_int(block, pos, 7)
                value = block[pos : pos + vlen].decode("latin1")
                pos += vlen
                if name:
                    headers[name] = value
            else:  # never-indexed / dynamic table: beyond this decoder
                return headers
    except (IndexError, UnicodeDecodeError):
        pass
    return headers


class H2Conn:
    """Minimal HTTP/2 client: preface, HEADERS, DATA, RST, frame loop."""

    def __init__(
        self, host: str, port: int, use_tls: bool = False, timeout: float = 8.0
    ) -> None:
        self.host = (host or "").strip()
        if not self.host:
            raise ValueError("host required")
        if not 1 <= int(port) <= 65535:
            raise ValueError("port must be 1-65535")
        self.port = int(port)
        self.use_tls = use_tls
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self._next_stream = 1

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
            if raw.selected_alpn_protocol() not in (None, "h2"):
                raw.close()
                raise ConnectionError("server did not negotiate h2")
        raw.settimeout(self.timeout)
        raw.sendall(
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + self._frame(_F_SETTINGS, 0, 0, b"")
        )
        self.sock = raw

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        finally:
            self.sock = None

    @staticmethod
    def _frame(ftype: int, flags: int, stream: int, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))[1:]
            + bytes([ftype, flags])
            + struct.pack(">I", stream & 0x7FFFFFFF)
            + payload
        )

    def _recv_exact(self, n: int) -> bytes:
        assert self.sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("peer closed")
            buf += chunk
        return buf

    def read_frame(self) -> tuple[int, int, int, bytes]:
        hdr = self._recv_exact(9)
        length = struct.unpack(">I", b"\x00" + hdr[:3])[0]
        return (
            hdr[3],
            hdr[4],
            struct.unpack(">I", hdr[5:9])[0] & 0x7FFFFFFF,
            (self._recv_exact(length) if length else b""),
        )

    def headers(self, path: str, end_stream: bool = False) -> int:
        assert self.sock is not None
        scheme = "https" if self.use_tls else "http"
        block = b"".join(
            [
                _hpack_literal(":method", "POST"),
                _hpack_literal(":scheme", scheme),
                _hpack_literal(":path", path),
                _hpack_literal(":authority", f"{self.host}:{self.port}"),
                _hpack_literal("content-type", "application/grpc"),
                _hpack_literal("te", "trailers"),
            ]
        )
        stream = self._next_stream
        self._next_stream += 2
        flags = _FLAG_END_HEADERS | (_FLAG_END_STREAM if end_stream else 0)
        self.sock.sendall(self._frame(_F_HEADERS, flags, stream, block))
        return stream

    def data(self, stream: int, payload: bytes, end_stream: bool = True) -> None:
        assert self.sock is not None
        flags = _FLAG_END_STREAM if end_stream else 0
        self.sock.sendall(self._frame(_F_DATA, flags, stream, payload))

    @staticmethod
    def grpc_wrap(message: bytes, compressed: bool = False) -> bytes:
        return (
            bytes([1 if compressed else 0]) + struct.pack(">I", len(message)) + message
        )


def _drain_unary(conn: H2Conn, stream: int) -> dict[str, Any]:
    """Read frames until stream trailers/close; return data + status."""
    data = b""
    trailers: dict[str, str] = {}
    saw_data = False
    try:
        while True:
            ftype, flags, fstream, payload = conn.read_frame()
            if fstream not in (0, stream):
                continue
            if ftype == _F_DATA and fstream == stream:
                saw_data = True
                data += payload
                if flags & _FLAG_END_STREAM:
                    break
            elif ftype == _F_HEADERS and fstream == stream:
                headers = _hpack_decode(payload)
                if "grpc-status" in headers or flags & _FLAG_END_STREAM:
                    trailers.update(headers)
                    if flags & _FLAG_END_STREAM:
                        break
            elif ftype == _F_RST and fstream == stream:
                code = struct.unpack(">I", payload[:4])[0] if len(payload) >= 4 else 0
                return {
                    "data": data,
                    "trailers": trailers,
                    "rst": code,
                    "saw_data": saw_data,
                }
            elif ftype == _F_GOAWAY:
                return {
                    "data": data,
                    "trailers": trailers,
                    "goaway": True,
                    "saw_data": saw_data,
                }
    except (ConnectionError, OSError, struct.error) as exc:
        return {
            "data": data,
            "trailers": trailers,
            "error": str(exc)[:160],
            "saw_data": saw_data,
        }
    return {"data": data, "trailers": trailers, "saw_data": saw_data}


def reflect_services(
    host: str, port: int, use_tls: bool = False, timeout: float = 8.0
) -> dict[str, Any]:
    """Ask the reflection endpoint for its service list (heuristic parse)."""
    conn = H2Conn(host, port, use_tls=use_tls, timeout=timeout)
    try:
        conn.connect()
        stream = conn.headers(
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
        )
        conn.data(stream, conn.grpc_wrap(b"\x0a\x00"))
        out = _drain_unary(conn, stream)
    finally:
        conn.close()
    names: list[str] = []
    for match in _NAME_RE.findall(out.get("data") or b""):
        token = match.decode()
        if "." in token and token not in names:
            names.append(token)
    return {
        "host": host,
        "port": port,
        "services": names[:64],
        "service_count": len(names),
        "reflection": bool(names),
        "trailers": out.get("trailers", {}),
        "heuristic": True,
        "note": "names are string-scanned from raw bytes, not proto-decoded",
    }


def _fuzz_shapes(seed: bytes) -> list[tuple[str, bytes]]:
    """(mutation, full DATA payload incl. 5-byte gRPC prefix)."""

    def wrap(msg: bytes, flag: int = 0, declared: int | None = None) -> bytes:
        return (
            bytes([flag])
            + struct.pack(">I", declared if declared is not None else len(msg))
            + msg
        )

    big = (seed[:64] if seed else b"A") * 4096  # 256 KiB
    return [
        ("oversize-length", wrap(seed, declared=len(seed) + 65536)),
        ("truncated-body", wrap(seed)[:3]),
        ("compressed-flag-lie", wrap(b"\x1f\x8b" + seed[:32], flag=1)),
        ("empty-message", wrap(b"")),
        ("garbage-message", wrap(os.urandom(64))),
        ("double-message", wrap(seed) + wrap(seed)),
        ("huge-message", wrap(big)),
        ("rst-after-headers", b""),  # special-cased: RST_STREAM instead of DATA
    ]


def fuzz_method(
    host: str,
    port: int,
    path: str,
    seed: str = "",
    iterations: int = 40,
    use_tls: bool = False,
    timeout: float = 5.0,
    rng_seed: int | None = None,
    progress: Callable[[str, float], None] | None = None,
) -> dict[str, Any]:
    """Replay mutated gRPC frames at one method; collect transport signals."""
    if not (path or "").strip().startswith("/"):
        raise ValueError("method path must look like /package.Service/Method")
    iterations = max(1, min(int(iterations or 40), 200))
    rng = random.Random(  # nosec B311 - deterministic fuzz RNG, not cryptographic
        rng_seed if rng_seed is not None else 0x4752
    )
    seed_bytes = seed.encode("utf-8", errors="replace")
    shapes = _fuzz_shapes(seed_bytes)
    candidates: list[dict[str, Any]] = []
    sent = 0
    for i in range(iterations):
        name, payload = shapes[rng.randrange(len(shapes))]
        conn = H2Conn(host, port, use_tls=use_tls, timeout=timeout)
        signal = "none"
        evidence = "clean reply"
        try:
            conn.connect()
            stream = conn.headers(path)
            if name == "rst-after-headers":
                assert conn.sock is not None
                conn.sock.sendall(conn._frame(_F_RST, 0, stream, struct.pack(">I", 8)))
            else:
                conn.data(stream, payload)
            out = _drain_unary(conn, stream)
            status = (out.get("trailers") or {}).get("grpc-status")
            if out.get("goaway"):
                signal, evidence = "goaway", "server sent GOAWAY"
            elif out.get("rst") is not None:
                signal, evidence = "rst", f"server reset stream (code {out['rst']})"
            elif out.get("error"):
                signal, evidence = "dropped", str(out["error"])[:160]
            elif status not in (None, "", "0"):
                signal, evidence = "grpc-error", f"trailer grpc-status: {status}"
        except (ConnectionError, OSError, ssl.SSLError, ValueError) as exc:
            message = str(exc)[:160]
            if "timed out" in message or "Timeout" in message:
                signal, evidence = "timeout", message
            else:
                signal, evidence = "dropped", message
        finally:
            conn.close()
        sent += 1
        if signal != "none":
            candidates.append(
                {
                    "mutation": name,
                    "iteration": i,
                    "method": path,
                    "signal": signal,
                    "evidence": evidence[:200],
                }
            )
        if progress and (i + 1) % 10 == 0:
            progress(f"grpc fuzz {i + 1}/{iterations}", (i + 1) / iterations * 100.0)
    return {
        "host": host,
        "port": port,
        "method": path,
        "iterations": sent,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": not candidates,
    }


def enumerate_and_fuzz(
    host: str,
    port: int,
    method: str = "",
    seed: str = "",
    iterations: int = 40,
    use_tls: bool = False,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Reflect (best-effort), then fuzz the chosen or first method."""
    try:
        enum = reflect_services(host, port, use_tls=use_tls, timeout=timeout)
    except (ConnectionError, OSError, ssl.SSLError, ValueError) as exc:
        return {
            "host": host,
            "port": port,
            "services": [],
            "reflection": False,
            "error": str(exc)[:200],
            "candidates": [],
            "clean": True,
        }
    target = (method or "").strip()
    if not target and enum.get("services"):
        target = f"/{enum['services'][0]}/Fuzz"
    if not target:
        return {
            **enum,
            "candidates": [],
            "candidate_count": 0,
            "clean": True,
            "note": "reflection empty; no method to fuzz",
        }
    fuzzed = fuzz_method(
        host,
        port,
        target,
        seed=seed,
        iterations=iterations,
        use_tls=use_tls,
        timeout=timeout,
    )
    return {**enum, **fuzzed}


def to_ledger(
    host: str, port: int, services: list[str], candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map reflection + fuzz signals to engagement vuln rows."""
    rows: list[dict[str, Any]] = []
    if services:
        rows.append(
            {
                "host": host,
                "name": f"grpc reflection enabled on {host}:{port} ({len(services)} services)"[
                    :220
                ],
                "severity": "MEDIUM",
                "module": "grpc-fuzz",
                "reference": "",
                "cwe": "CWE-200",
                "detail": f"services={', '.join(services[:12])}".strip()[:400],
            }
        )
    for cand in candidates:
        rows.append(
            {
                "host": host,
                "name": f"grpc-fuzz {cand.get('mutation')} ({cand.get('signal')}) {cand.get('method', '')}"[
                    :220
                ],
                "severity": (
                    "HIGH"
                    if cand.get("signal") in ("dropped", "goaway", "rst")
                    else "MEDIUM"
                ),
                "module": "grpc-fuzz",
                "reference": "",
                "cwe": "CWE-20",
                "detail": f"method={cand.get('method', '')} evidence={cand.get('evidence', '')}".strip()[
                    :400
                ],
            }
        )
    return rows


def sandbox_enumeration(host: str = "127.0.0.1", port: int = 50051) -> dict[str, Any]:
    """Canned enumeration + fuzz (no sockets opened)."""
    candidates = [
        {
            "mutation": "oversize-length",
            "iteration": 2,
            "method": "/lab.Echo/Echo",
            "signal": "rst",
            "evidence": "server reset stream (code 8) (sandbox)",
        },
        {
            "mutation": "garbage-message",
            "iteration": 7,
            "method": "/lab.Echo/Echo",
            "signal": "grpc-error",
            "evidence": "trailer grpc-status: 13 (sandbox)",
        },
    ]
    return {
        "host": host,
        "port": port,
        "services": ["lab.Echo", "lab.Admin"],
        "service_count": 2,
        "reflection": True,
        "heuristic": True,
        "method": "/lab.Echo/Echo",
        "iterations": 8,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": False,
        "sandbox": True,
    }
