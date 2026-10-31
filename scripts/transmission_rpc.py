#!/usr/bin/env python3
"""Transmission RPC helper for authorized lab work.

Talks to a Transmission daemon's RPC interface (the same one h4k's
toolkit would drive) and can:

  * read the session/config
  * set settings
  * add torrents

Used by the h4k engagement workflow to drive a Transmission-based lab target.
"""

from __future__ import annotations

import base64
import json
import sys
import urllib.error
import urllib.request

RPC_PATH = "/transmission/rpc"


def _benc(value) -> bytes:
    """Minimal bencode encoder."""
    if isinstance(value, int):
        return b"i%de" % value
    if isinstance(value, bytes):
        return b"%d:%s" % (len(value), value)
    if isinstance(value, str):
        return _benc(value.encode())
    if isinstance(value, list):
        return b"l" + b"".join(_benc(v) for v in value) + b"e"
    if isinstance(value, dict):
        out = b"d"
        for key in sorted(value):
            out += _benc(key) + _benc(value[key])
        return out + b"e"
    raise TypeError(type(value))


def empty_torrent(name: str = "h4k-probe") -> bytes:
    """A zero-length torrent: it is 'complete' the moment it is added."""
    info = {
        "name": name,
        "length": 0,
        "piece length": 16384,
        "pieces": b"",
    }
    return _benc({"announce": "", "created by": "h4k", "info": info})


class Transmission:
    def __init__(
        self, host: str, port: int = 9091, path: str = RPC_PATH, timeout: int = 20
    ):
        self.url = f"http://{host}:{port}{path}"
        self.timeout = timeout
        self.session_id: str | None = None

    def rpc(self, method: str, args: dict | None = None) -> dict:
        payload = json.dumps({"method": method, "arguments": args or {}}).encode()
        headers = {"Content-Type": "application/json"}
        if self.session_id:
            headers["X-Transmission-Session-Id"] = self.session_id
        req = urllib.request.Request(self.url, data=payload, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                sid = resp.headers.get("X-Transmission-Session-Id")
                if sid:
                    self.session_id = sid
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            sid = exc.headers.get("X-Transmission-Session-Id")
            if sid:
                self.session_id = sid
                req = urllib.request.Request(
                    self.url,
                    data=payload,
                    headers=headers | {"X-Transmission-Session-Id": sid},
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode())
            raise

    def session_get(self) -> dict:
        return self.rpc("session-get").get("arguments", {})

    def session_set(self, settings: dict) -> dict:
        return self.rpc("session-set", settings)

    def torrent_add(self, **kwargs) -> dict:
        return self.rpc("torrent-add", kwargs)


def main() -> int:
    if len(sys.argv) < 4:
        print("usage: transmission_rpc.py <host> <command> [key=value ...]")
        print("commands: session-get | session-set | torrent-add-empty")
        return 2
    host = sys.argv[1]
    cmd = sys.argv[2]
    t = Transmission(host)
    if cmd == "session-get":
        print(json.dumps(t.session_get(), indent=2))
    elif cmd == "session-set":
        settings = {}
        for arg in sys.argv[3:]:
            key, _, val = arg.partition("=")
            settings[key] = json.loads(val)
        print(json.dumps(t.session_set(settings), indent=2))
    elif cmd == "torrent-add-empty":
        meta = base64.b64encode(empty_torrent()).decode()
        res = t.torrent_add(metainfo=meta, paused=False)
        print(json.dumps(res, indent=2))
    else:
        print(f"unknown command {cmd}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
