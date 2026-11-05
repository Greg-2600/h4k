"""PCAP → seeds card through the real UI (sandbox canned)."""

from __future__ import annotations

import base64
import struct
from typing import Any

from .helpers import click, fill, go_to, wait_text, wait_visible


def _tiny_pcap() -> str:
    def frame(payload: bytes) -> bytes:
        def ip(s: str) -> bytes:
            return bytes(int(x) for x in s.split("."))

        eth = b"\x00" * 12 + struct.pack(">H", 0x0800)
        iph = (
            bytes([0x45, 0x00])
            + struct.pack(">HHHBBH", 40 + len(payload), 1, 0, 64, 6, 0)
            + ip("10.0.0.9")
            + ip("10.0.0.5")
        )
        tcph = struct.pack(">HHIIBBHHH", 43210, 80, 1000, 0, 0x50, 0x10, 8192, 0, 0)
        return eth + iph + tcph + payload

    out = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    payload = b"GET / HTTP/1.0\r\n\r\n"
    out += struct.pack("<IIII", 0, 0, 14 + 40 + len(payload), 14 + 40 + len(payload))
    out += frame(payload)
    return base64.b64encode(bytes(out)).decode()


def test_pcap_parse_and_replay(page: Any, seeded: dict[str, Any]) -> None:
    go_to(page, "exploit")
    fill(page, "pcap-b64", _tiny_pcap())
    click(page, "btn-pcap-seeds")
    wait_visible(page, "pcap-output", timeout=60)
    wait_text(page, "pcap-output", "seed(s)", timeout=60)
