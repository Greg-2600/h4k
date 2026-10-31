#!/usr/bin/env python3
"""Minimal HTTP tracker for authorized lab work.

Answers `announce` requests with a single peer (our seeder), so a client that
only knows the .torrent can still find the peer that has the data. This is
what makes a lab torrent finish in one second instead of waiting for the
public swarm.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


class Handler(BaseHTTPRequestHandler):
    peer = "127.0.0.1:6881"
    serve_dir = "."

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path.startswith("/announce"):
            query = parse_qs(parsed.query)
            interval = query.get("interval", ["60"])[0]
            host, _, port = self.peer.partition(":")
            style = (os.environ.get("TRACKER_STYLE") or "compact").lower()
            if style == "compact":
                # Compact peers: 4-byte IPv4 + 2-byte port, big endian.
                body = socket.inet_aton(host) + struct.pack(">H", int(port))
                ctype = "text/plain"
            elif style == "bencode":
                # BEP 48 bencoded response.
                body = (
                    b"d8:intervali"
                    + str(interval).encode()
                    + b"e5:peers6:"
                    + socket.inet_aton(host)
                    + struct.pack(">H", int(port))
                    + b"ee"
                )
                ctype = "text/plain"
            else:
                body = (
                    b'{"interval":'
                    + str(interval).encode()
                    + b',"peers":[{"ip":"'
                    + host.encode()
                    + b'","port":'
                    + port.encode()
                    + b"}]}"
                )
                ctype = "application/json"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        # also serve the .torrent files from --dir (the client fetches the
        # metadata from here before it ever talks to a peer)
        name = os.path.basename(parsed.path)
        path = os.path.join(self.serve_dir, name)
        if not name or not os.path.isfile(path):
            self.send_error(404)
            return
        with open(path, "rb") as handle:
            body = handle.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-bittorrent")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:
        print("[tracker] " + fmt % args, flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="minimal HTTP tracker")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=6883)
    parser.add_argument("--peer", default="127.0.0.1:6881", help="peer to hand out")
    parser.add_argument(
        "--dir", default=".", help="directory with .torrent files to serve"
    )
    args = parser.parse_args()
    Handler.peer = args.peer
    Handler.serve_dir = args.dir
    server = HTTPServer((args.host, args.port), Handler)
    print(
        f"[tracker] listening on {args.host}:{args.port}, handing out peer {args.peer}"
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
