#!/usr/bin/env python3
"""Minimal BitTorrent seeder for authorized lab work.

Serves a single piece to a peer so that a magnet-driven client can complete a
torrent *immediately* -- which is what makes Transmission's
`script-torrent-done` hook fire (the classic "torrent completes -> run a
script" chain used in lab work against your own machines).

It speaks just enough of the peer wire protocol for one piece:
handshake -> bitfield -> unchoke -> request/piece.

Usage:
    python3 scripts/torrent_seeder.py --host 0.0.0.0 --port 6881 \\
        --payload /path/to/payload.bin [--info-hash HEX]
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import socket
import struct
import threading

PIECE_LEN = 16384
PROTOCOL = b"BitTorrent protocol"


def build_info_hash(payload: bytes, name: str = "h4k-payload.bin") -> tuple[str, bytes]:
    """Return (hex infohash, bencoded info dict) for a single-file torrent.

    The name is part of the info dict, so it decides the info hash -- the
    seeder and the .torrent must agree on it or the peer handshake is
    rejected.
    """
    pieces = b""
    for i in range(0, max(len(payload), 1), PIECE_LEN):
        piece = payload[i : i + PIECE_LEN]
        if not payload:
            piece = b""
        pieces += hashlib.sha1(piece).digest()
    info = {
        "length": len(payload),
        "name": name,
        "piece length": PIECE_LEN,
        "pieces": pieces,
    }

    # bencode (sorted keys, no dict ordering surprises)
    def benc(value) -> bytes:
        if isinstance(value, int):
            return b"i%de" % value
        if isinstance(value, bytes):
            return b"%d:%s" % (len(value), value)
        if isinstance(value, str):
            return benc(value.encode())
        if isinstance(value, list):
            return b"l" + b"".join(benc(v) for v in value) + b"e"
        if isinstance(value, dict):
            out = b"d"
            for key in sorted(value):
                out += benc(key) + benc(value[key])
            return out + b"e"
        raise TypeError(type(value))

    encoded = benc(info)
    return hashlib.sha1(encoded).hexdigest(), encoded


def _read_exactly(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf += chunk
    return buf


def handle(
    conn: socket.socket, info_hash: bytes, payload: bytes, port: int, info_bytes: bytes
) -> None:
    try:
        # --- handshake (receive) ---
        conn.settimeout(10)
        try:
            header = conn.recv(68)
        except Exception as exc:
            print(f"[seeder] recv failed: {exc}", flush=True)
            return
        print(f"[seeder] raw recv {len(header)} bytes: {header[:40].hex()}", flush=True)
        if len(header) < 68:
            print("[seeder]   short handshake - dropping", flush=True)
            return
        # the handshake starts with a 1-byte length prefix (0x13 = 19), so the
        # protocol string starts at offset 1
        if len(header) < 68 or header[1:20] != PROTOCOL:
            print("[seeder]   not a BitTorrent handshake - dropping", flush=True)
            return
        peer_hash = header[28:48]
        print(
            f"[seeder] handshake from peer; want={info_hash.hex()} got={peer_hash.hex()}",
            flush=True,
        )
        if peer_hash != info_hash:
            print("[seeder]   info hash mismatch - dropping", flush=True)
            return
        # --- handshake (send) ---
        # Wire format: 1 byte pstrlen (19) + "BitTorrent protocol" + 8 reserved
        # bytes (last 2 = our port) + 20 byte info hash + 20 byte peer id = 68.
        # All-zero reserved: no muTP port advertisement, so the peer stays on
        # plain TCP (and clients that read the last reserved byte as a muTP
        # port do not try to reach us over UDP).
        reserved = b"\x00" * 8
        peer_id = b"-h4k01" + b"\x00" * 14  # exactly 20 bytes
        our_hs = b"\x13" + PROTOCOL + reserved + info_hash + peer_id
        print(
            f"[seeder] our handshake ({len(our_hs)} bytes): {our_hs.hex()}", flush=True
        )
        conn.sendall(our_hs)
        # --- bitfield: we have every piece ---
        n_pieces = max(1, (len(payload) + PIECE_LEN - 1) // PIECE_LEN)
        bits = bytearray((n_pieces + 7) // 8)
        for i in range(n_pieces):
            bits[i // 8] |= 0x80 >> (i % 8)
        # message id 5 = bitfield, id 1 = unchoke
        conn.sendall(struct.pack(">IB", 1 + len(bits), 5) + bytes(bits))
        # --- unchoke ---
        conn.sendall(struct.pack(">IB", 1, 1))
        # --- serve requests ---
        while True:
            header = _read_exactly(conn, 4)
            length = struct.unpack(">I", header)[0]
            body = _read_exactly(conn, length)
            msg_id = body[0]
            print(f"[seeder] recv msg id={msg_id} len={length}", flush=True)
            if msg_id == 6:  # request
                index, begin, want = struct.unpack(">III", body[1:13])
                print(
                    f"[seeder]   request piece={index} begin={begin} want={want}",
                    flush=True,
                )
                if index == 0xFFFFFFFF:
                    # metadata request (magnet): index -1, the bencoded info
                    block = info_bytes[begin : begin + want]
                    conn.sendall(
                        struct.pack(">IB", 9 + len(block), 7)
                        + struct.pack(">II", index, begin)
                        + block
                    )
                    print(f"[seeder]   sent metadata ({len(block)} bytes)", flush=True)
                    continue
                piece = payload[index * PIECE_LEN : (index + 1) * PIECE_LEN]
                block = piece[begin : begin + want]
                conn.sendall(
                    struct.pack(">IB", 9 + len(block), 7)
                    + struct.pack(">II", index, begin)
                    + block
                )
                print(f"[seeder]   sent piece ({len(block)} bytes)", flush=True)
            elif msg_id in (0, 4):  # keep-alive / interested
                continue
    except Exception as exc:
        print(f"[seeder] handler error: {exc!r}", flush=True)
    finally:
        with contextlib.suppress(Exception):
            conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="minimal BitTorrent seeder")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=6881)
    parser.add_argument(
        "--payload", required=True, help="file to serve as the only piece"
    )
    parser.add_argument(
        "--name",
        default="h4k-payload.bin",
        help="file name the .torrent advertises (part of the info hash)",
    )
    args = parser.parse_args()

    with open(args.payload, "rb") as handle:
        payload = handle.read()
    info_hash_hex, info_bytes = build_info_hash(payload, args.name)
    info_hash = bytes.fromhex(info_hash_hex)
    print(f"[seeder] info hash: {info_hash_hex}", flush=True)
    print(f"[seeder] payload: {len(payload)} bytes", flush=True)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(8)
    print(f"[seeder] listening on {args.host}:{args.port}", flush=True)
    while True:
        conn, addr = server.accept()
        print(f"[seeder] peer connected: {addr[0]}:{addr[1]}", flush=True)
        threading.Thread(
            target=handle,
            args=(conn, info_hash, payload, args.port, info_bytes),
            daemon=True,
        ).start()


if __name__ == "__main__":
    raise SystemExit(main())
