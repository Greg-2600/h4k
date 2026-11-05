"""PCAP → seed replay — deterministic fuzz seeds (Backlog #55).

Offline, dependency-free PCAP parsing that turns captured traffic
into deterministic fuzz seeds: a minimal hand-rolled reader handles
the global header (micro/nanosecond, either endianness), Ethernet
(with 802.1Q), IPv4 and TCP, groups packets into directed flows, and
reassembles each flow's payload in sequence order (overlaps dropped,
fragments after the first skipped — stated limits, not silent magic).

Each flow with payload bytes becomes one seed (base64 + size +
packet count), identical pcaps always yielding identical seeds. An
opt-in `replay` step opens a plain TCP connection to the operator's
lab target and re-sends one flow verbatim, recording the response
excerpt — same bytes, same order, every time. Nothing is uploaded
anywhere: pasted base64 or a server-side path under the data dir.

Sandbox returns canned flows without parsing anything. Crash-to-
corpus import for these seeds activates with the shared-corpus change
(the service already tags them `pcap`).
"""

from __future__ import annotations

import base64
import contextlib
import logging
import socket
import struct
from typing import Any

logger = logging.getLogger("h4k.pcap_seeds")

MAX_PCAP_BYTES = 5_000_000
MAX_PACKETS = 20_000
MAX_FLOWS = 512

_MAGICS = {
    0xA1B2C3D4: (">", 1_000_000),
    0xD4C3B2A1: ("<", 1_000_000),
    0xA1B23C4D: (">", 1_000_000_000),
    0x4D3CB2A1: ("<", 1_000_000_000),
}


def _ip(addr: bytes) -> str:
    return ".".join(str(b) for b in addr)


def parse_pcap(raw: bytes) -> dict[str, Any]:
    """Parse packets into directed TCP flows with reassembled payloads."""
    if len(raw) > MAX_PCAP_BYTES:
        raise ValueError(f"pcap exceeds {MAX_PCAP_BYTES} bytes")
    if len(raw) < 24:
        raise ValueError("too short for a pcap global header")
    magic = struct.unpack(">I", raw[:4])[0]
    if magic not in _MAGICS:
        magic = struct.unpack("<I", raw[:4])[0]
    if magic not in _MAGICS:
        raise ValueError("not a pcap (bad magic)")
    endian, _ = _MAGICS[magic]
    off = 24
    flows: dict[str, dict[str, Any]] = {}
    packets = 0
    skipped = 0
    order: list[str] = []
    while off + 16 <= len(raw) and packets < MAX_PACKETS:
        ts_sec, _, caplen, _wirelen = struct.unpack(
            endian + "IIII", raw[off : off + 16]
        )
        off += 16
        frame = raw[off : off + caplen]
        off += caplen
        packets += 1
        parsed = _parse_frame(frame)
        if parsed is None:
            skipped += 1
            continue
        key = "|".join(str(x) for x in parsed[:4])
        if key not in flows:
            if len(flows) >= MAX_FLOWS:
                skipped += 1
                continue
            flows[key] = {
                "src": parsed[0],
                "sport": parsed[1],
                "dst": parsed[2],
                "dport": parsed[3],
                "segments": [],
                "packets": 0,
                "first_seen": ts_sec,
            }
            order.append(key)
        flow = flows[key]
        flow["segments"].append((parsed[4], parsed[5]))
        flow["packets"] += 1
    out_flows: list[dict[str, Any]] = []
    for key in order:
        flow = flows[key]
        payload = _reassemble(flow["segments"])
        out_flows.append(
            {
                "key": key,
                "src": flow["src"],
                "sport": flow["sport"],
                "dst": flow["dst"],
                "dport": flow["dport"],
                "packets": flow["packets"],
                "bytes": len(payload),
                "payload_b64": base64.b64encode(payload).decode() if payload else "",
            }
        )
    seeds = [
        {"flow": f["key"], "size": f["bytes"], "seed_b64": f["payload_b64"]}
        for f in out_flows
        if f["bytes"]
    ]
    return {
        "packets": packets,
        "skipped": skipped,
        "flows": out_flows,
        "flow_count": len(out_flows),
        "seeds": seeds,
        "seed_count": len(seeds),
    }


def _parse_frame(frame: bytes) -> tuple[str, int, str, int, int, bytes] | None:
    """Ethernet → IPv4 → TCP; None when the frame is not usable."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack(">H", frame[12:14])[0]
    off = 14
    if ethertype == 0x8100:  # 802.1Q
        if len(frame) < 18:
            return None
        ethertype = struct.unpack(">H", frame[16:18])[0]
        off = 18
    if ethertype != 0x0800 or len(frame) < off + 20:
        return None
    ver_ihl = frame[off]
    ihl = (ver_ihl & 0x0F) * 4
    if (ver_ihl >> 4) != 4 or ihl < 20 or len(frame) < off + ihl:
        return None
    flags_frag = struct.unpack(">H", frame[off + 6 : off + 8])[0]
    if flags_frag & 0x1FFF or flags_frag & 0x2000:  # non-first fragment
        return None
    if frame[off + 9] != 6:  # TCP only
        return None
    src = _ip(frame[off + 12 : off + 16])
    dst = _ip(frame[off + 16 : off + 20])
    base = off + ihl
    if len(frame) < base + 20:
        return None
    sport, dport = struct.unpack(">HH", frame[base : base + 4])
    seq = struct.unpack(">I", frame[base + 4 : base + 8])[0]
    data_off = (frame[base + 12] >> 4) * 4
    if data_off < 20:
        return None
    return (src, sport, dst, dport, seq, frame[base + data_off :])


def _reassemble(segments: list[tuple[int, bytes]]) -> bytes:
    out = bytearray()
    expected: int | None = None
    for seq, data in sorted(segments, key=lambda s: s[0]):
        if not data:
            continue
        if expected is None or seq >= expected:
            out.extend(data)
            expected = seq + len(data)
        elif seq + len(data) > (expected or 0):
            out.extend(data[expected - seq :])
            expected = seq + len(data)
    return bytes(out)


def replay_flow(
    host: str, port: int, payload: bytes, timeout: float = 8.0
) -> dict[str, Any]:
    """Re-send one flow verbatim over TCP; record the response excerpt."""
    import time

    host = (host or "").strip()
    if not host or not 1 <= int(port) <= 65535:
        raise ValueError("host and port 1-65535 required")
    if not payload:
        raise ValueError("empty payload replays nothing")
    started = time.time()
    try:
        sock = socket.create_connection((host, int(port)), timeout=timeout)
    except OSError as exc:
        return {
            "connected": False,
            "error": str(exc)[:160],
            "elapsed": round(time.time() - started, 2),
        }
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        try:
            with contextlib.suppress(OSError):
                sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                try:
                    chunk = sock.recv(8192)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(map(len, chunks)) >= 8192:
                    break
        finally:
            sock.close()
        body = b"".join(chunks)
        return {
            "connected": True,
            "sent": len(payload),
            "received": len(body),
            "response": body[:512].decode("utf-8", errors="replace"),
            "elapsed": round(time.time() - started, 2),
        }
    except OSError as exc:
        return {
            "connected": False,
            "error": str(exc)[:160],
            "elapsed": round(time.time() - started, 2),
        }


def load_source(source: str) -> bytes:
    """Read pasted base64 (or base64:…) — server-side paths stay out."""
    text = (source or "").strip()
    if text.startswith("base64:"):
        text = text[len("base64:") :].strip()
    if not text:
        raise ValueError("pcap required (paste base64)")
    try:
        return base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise ValueError(f"not valid base64: {exc}") from exc


def sandbox_parse() -> dict[str, Any]:
    """Canned parse + replay (nothing parsed, nothing sent)."""
    payload = b"GET / HTTP/1.0\r\n\r\n"
    seed = base64.b64encode(payload).decode()
    flow = {
        "key": "10.0.0.9|43210|10.0.0.5|80",
        "src": "10.0.0.9",
        "sport": 43210,
        "dst": "10.0.0.5",
        "dport": 80,
        "packets": 3,
        "bytes": len(payload),
        "payload_b64": seed,
    }
    return {
        "packets": 5,
        "skipped": 2,
        "flows": [flow],
        "flow_count": 1,
        "seeds": [{"flow": flow["key"], "size": flow["bytes"], "seed_b64": seed}],
        "seed_count": 1,
        "replay": {
            "connected": True,
            "sent": len(payload),
            "received": 64,
            "response": "HTTP/1.0 200 OK (sandbox)",
            "elapsed": 0.02,
        },
        "sandbox": True,
    }
