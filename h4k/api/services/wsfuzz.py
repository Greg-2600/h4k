"""WebSocket fuzz — frame mutation + replay (Backlog #45).

Opt-in, lab-only fuzzing of one WebSocket endpoint YOU own. A minimal
RFC 6455 client (stdlib sockets only — no new dependencies) replays an
operator-supplied seed message through deterministic mutations and
records crash signals: dropped connections, abnormal close codes,
timeouts, and error text that leaks back through the socket.

Mutations (seeded RNG, reproducible): bit flips, truncation, chunk
repeat, empty frame, oversize frame, format-string tokens, JSON
structure breaks, null/newline injection, unicode bomb, giant numbers.

Each iteration opens a fresh connection (clean isolation), sends one
mutated frame, and waits for one reply. Findings ledger as engagement
vulns on the URL host when `engagement_id` is given (scope-enforced).
Sandbox returns canned candidates without opening any socket.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import random
import re
import socket
import ssl
import struct
import urllib.parse
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.wsfuzz")

_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

ERROR_RE = re.compile(
    r"traceback|exception|panic|fatal|segfault|stack overflow|"
    r"ora-\d+|sql syntax|psycopg|pymongo|node\.js|panic:|Traceback",
    re.IGNORECASE,
)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed mid-frame")
        buf += chunk
    return buf


class WsClient:
    """Minimal RFC 6455 client: handshake, masked text send, frame recv."""

    def __init__(self, url: str, timeout: float = 8.0) -> None:
        parts = urllib.parse.urlsplit((url or "").strip())
        if parts.scheme not in ("ws", "wss"):
            raise ValueError("url must be ws:// or wss://")
        if not parts.hostname:
            raise ValueError("url must include a host")
        self.parts = parts
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def connect(self) -> None:
        host = self.parts.hostname or ""
        port = self.parts.port or (443 if self.parts.scheme == "wss" else 80)
        raw = socket.create_connection((host, port), timeout=self.timeout)
        if self.parts.scheme == "wss":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=host)
        raw.settimeout(self.timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        path = self.parts.path or "/"
        if self.parts.query:
            path += "?" + self.parts.query
        raw.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = raw.recv(4096)
            if not chunk:
                raw.close()
                raise ConnectionError("handshake: peer closed")
            head += chunk
            if len(head) > 16384:
                raw.close()
                raise ConnectionError("handshake: header too large")
        status = head.split(b"\r\n", 1)[0]
        if b" 101 " not in status:
            raw.close()
            raise ConnectionError(
                f"handshake refused: {status.decode(errors='replace')[:80]}"
            )
        accept = hashlib.sha1((key + _GUID).encode()).digest()
        if base64.b64encode(accept) not in head:
            raw.close()
            raise ConnectionError("handshake: bad accept key")
        self.sock = raw

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.sendall(b"\x88\x80" + os.urandom(4))
        except OSError:
            pass
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        finally:
            self.sock = None

    def send_text(self, data: bytes) -> None:
        if not self.sock:
            raise ConnectionError("not connected")
        mask = os.urandom(4)
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        header = bytes([0x81])
        n = len(payload)
        if n < 126:
            header += bytes([0x80 | n])
        elif n < 65536:
            header += bytes([0x80 | 126]) + struct.pack(">H", n)
        else:
            header += bytes([0x80 | 127]) + struct.pack(">Q", n)
        self.sock.sendall(header + mask + payload)

    def recv_one(self) -> tuple[int, bytes]:
        """Return (opcode, payload); answers pings, raises on close/error."""
        if not self.sock:
            raise ConnectionError("not connected")
        hdr = _recv_exact(self.sock, 2)
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", _recv_exact(self.sock, 2))[0]
        elif length == 127:
            length = struct.unpack(">Q", _recv_exact(self.sock, 8))[0]
        mask = _recv_exact(self.sock, 4) if hdr[1] & 0x80 else b""
        payload = _recv_exact(self.sock, length) if length else b""
        if mask:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 0x9:  # ping -> pong
            if self.sock:
                self.sock.sendall(b"\x8a\x80" + os.urandom(4))
            return self.recv_one()
        if opcode == 0x8:  # close
            code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 1005
            raise ConnectionError(f"peer sent close ({code})")
        if opcode not in (0x1, 0x2):
            raise ConnectionError(f"unexpected opcode {opcode}")
        return opcode, payload


def _mut_bitflip(seed: bytes, rng: random.Random) -> bytes:
    if not seed:
        return b"\x00"
    data = bytearray(seed)
    for _ in range(max(1, len(data) // 8)):
        i = rng.randrange(len(data))
        data[i] ^= 1 << rng.randrange(8)
    return bytes(data)


def _mut_truncate(seed: bytes, rng: random.Random) -> bytes:
    if len(seed) < 2:
        return b""
    return seed[: rng.randrange(1, len(seed))]


def _mut_repeat(seed: bytes, rng: random.Random) -> bytes:
    if not seed:
        return seed
    i = rng.randrange(len(seed))
    chunk = seed[i : i + max(1, len(seed) // 4)]
    return seed + chunk * rng.randrange(2, 6)


def _mut_oversize(seed: bytes, rng: random.Random) -> bytes:
    _ = rng
    return (seed[:64] if seed else b"A") * 1024  # 64 KiB frame


def _mut_empty(seed: bytes, rng: random.Random) -> bytes:
    _ = (seed, rng)
    return b""


def _mut_format(seed: bytes, rng: random.Random) -> bytes:
    _ = rng
    toks = [b"%s", b"%x", b"%n", b"{0}", b"${7*7}", b"{{7*7}}"]
    tok = toks[rng.randrange(len(toks))]
    return seed + b" " + tok * 8 if seed else tok * 8


def _mut_json_break(seed: bytes, rng: random.Random) -> bytes:
    try:
        text = seed.decode("utf-8")
    except UnicodeDecodeError:
        return _mut_bitflip(seed, rng)
    if not text.lstrip().startswith(("{", "[")):
        return _mut_bitflip(seed, rng)
    breaks = [
        text.replace('"', "", 1),
        text + text,
        text.replace(":", ":null,", 1),
        '{"' + text,
        text[:-1] if len(text) > 1 else "",
    ]
    return breaks[rng.randrange(len(breaks))].encode("utf-8", errors="replace")


def _mut_null(seed: bytes, rng: random.Random) -> bytes:
    if not seed:
        return b"\x00"
    i = rng.randrange(len(seed) + 1)
    return seed[:i] + b"\x00" + seed[i:]


def _mut_newline(seed: bytes, rng: random.Random) -> bytes:
    _ = rng
    return seed + b"\r\n\r\nGET / HTTP/1.1\r\n\r\n" if seed else b"\n" * 64


def _mut_unicode(seed: bytes, rng: random.Random) -> bytes:
    _ = rng
    return ("ü" * 512 + (seed.decode("utf-8", errors="replace")[:64])).encode()


def _mut_giant_number(seed: bytes, rng: random.Random) -> bytes:
    _ = rng
    try:
        text = seed.decode("utf-8")
    except UnicodeDecodeError:
        return b"9" * 512
    m = re.search(r"-?\d+", text)
    if not m:
        return (text + " " + "9" * 128).encode()
    return (text[: m.start()] + "9" * 128 + text[m.end() :]).encode()


MUTATIONS: list[tuple[str, Callable[[bytes, random.Random], bytes]]] = [
    ("bitflip", _mut_bitflip),
    ("truncate", _mut_truncate),
    ("repeat", _mut_repeat),
    ("oversize", _mut_oversize),
    ("empty", _mut_empty),
    ("format", _mut_format),
    ("json-break", _mut_json_break),
    ("null-inject", _mut_null),
    ("newline-inject", _mut_newline),
    ("unicode-bomb", _mut_unicode),
    ("giant-number", _mut_giant_number),
]


def _signal(reply: bytes | None, error: str | None) -> tuple[str, str]:
    if error:
        if (
            "close (100" in error
            and "close (1000)" not in error
            and "close (1005)" not in error
        ):
            return "abnormal-close", error
        if "timed out" in error or "Timeout" in error:
            return "timeout", error
        return "dropped", error
    text = (reply or b"").decode("utf-8", errors="replace")
    if ERROR_RE.search(text):
        hit = ERROR_RE.search(text)
        return (
            "error-text",
            f"server leaked: …{(hit.group(0) if hit else 'error')[:60]}…",
        )
    return "none", "clean reply"


def fuzz_ws(
    url: str,
    seed: str = "",
    iterations: int = 50,
    timeout: float = 5.0,
    rng_seed: int | None = None,
    progress: Callable[[str, float], None] | None = None,
) -> dict[str, Any]:
    """Replay mutated seeds at one WS endpoint; collect crash signals."""
    if not (url or "").strip():
        raise ValueError("url required")
    iterations = max(1, min(int(iterations or 50), 500))
    rng = random.Random(  # nosec B311 - deterministic fuzz RNG, not cryptographic
        rng_seed if rng_seed is not None else 0x5746
    )
    seed_bytes = seed.encode("utf-8", errors="replace")
    candidates: list[dict[str, Any]] = []
    sent = 0
    for i in range(iterations):
        name, fn = MUTATIONS[i % len(MUTATIONS)]
        payload = fn(seed_bytes, rng)
        client = WsClient(url, timeout=timeout)
        error: str | None = None
        reply: bytes | None = None
        try:
            client.connect()
            client.send_text(payload)
            try:
                _, reply = client.recv_one()
            except (OSError, ConnectionError) as exc:
                error = str(exc)[:160]
        except (OSError, ConnectionError, ValueError, ssl.SSLError) as exc:
            error = str(exc)[:160]
        finally:
            client.close()
        sent += 1
        signal, evidence = _signal(reply, error)
        if signal != "none":
            candidates.append(
                {
                    "mutation": name,
                    "iteration": i,
                    "sent": payload[:256].decode("utf-8", errors="replace"),
                    "signal": signal,
                    "evidence": evidence[:200],
                    "reply": (reply or b"")[:256].decode("utf-8", errors="replace"),
                }
            )
        if progress and (i + 1) % 10 == 0:
            progress(f"ws fuzz {i + 1}/{iterations}", (i + 1) / iterations * 100.0)
    return {
        "url": url,
        "seed": seed[:256],
        "iterations": sent,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": not candidates,
    }


def to_ledger(
    host: str, url: str, candidates: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Map fuzz crash signals to engagement vuln rows for the URL host."""
    rows: list[dict[str, Any]] = []
    for cand in candidates:
        rows.append(
            {
                "host": host,
                "name": f"ws-fuzz {cand.get('mutation')} ({cand.get('signal')}) via {url}"[
                    :220
                ],
                "severity": (
                    "HIGH"
                    if cand.get("signal") in ("dropped", "abnormal-close")
                    else "MEDIUM"
                ),
                "module": "ws-fuzz",
                "reference": "",
                "cwe": "CWE-20",
                "detail": (
                    f"iteration={cand.get('iteration')} "
                    f"sent={cand.get('sent', '')} "
                    f"evidence={cand.get('evidence', '')}"
                ).strip()[:400],
            }
        )
    return rows


def sandbox_fuzz(url: str = "ws://lab.local/socket", seed: str = "") -> dict[str, Any]:
    """Canned fuzz result (no sockets opened)."""
    candidates = [
        {
            "mutation": "oversize",
            "iteration": 3,
            "sent": (seed or '{"hello":1}')[:64],
            "signal": "dropped",
            "evidence": "peer closed mid-frame (sandbox)",
            "reply": "",
        },
        {
            "mutation": "format",
            "iteration": 5,
            "sent": "%x %x %x (sandbox)",
            "signal": "error-text",
            "evidence": "server leaked: …exception… (sandbox)",
            "reply": "exception: bad format (sandbox)",
        },
    ]
    return {
        "url": url or "ws://lab.local/socket",
        "seed": (seed or "")[:256],
        "iterations": 8,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "clean": False,
        "sandbox": True,
    }
