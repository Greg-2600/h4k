#!/usr/bin/env python3
"""Run the h4k API directly on the host (no container).

Handy for development, for a laptop without Docker, and for the Selenium
suite (which starts the API in sandbox mode).

    python3 scripts/run_local.py                 # normal mode
    python3 scripts/run_local.py --sandbox       # deterministic, offline
    python3 scripts/run_local.py --port 3199     # custom port

The API needs Metasploit's RPC daemon for module execution; everything else
(recon, fingerprinting, CVE correlation, the toolkit, SAST/SCA, fuzzing) works
without it. Use --no-msf to start without touching msfrpcd at all.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

API_DIR = Path(__file__).resolve().parent.parent / "h4k" / "api"


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the h4k API on the host")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("API_PORT", 3137))
    )
    parser.add_argument(
        "--sandbox",
        action="store_true",
        help="deterministic offline mode (no network, no Metasploit)",
    )
    parser.add_argument(
        "--no-msf",
        action="store_true",
        help="do not configure a Metasploit client at all",
    )
    parser.add_argument(
        "--data-dir",
        default=os.environ.get("H4K_DATA_DIR", ""),
        help="runtime data directory (default: h4k/data)",
    )
    args = parser.parse_args()

    sys.path.insert(0, str(API_DIR))
    os.environ.setdefault("H4K_REFRESH_CVE", "1")
    os.environ.setdefault("H4K_AUTO_UPDATE", "1")
    os.environ.setdefault("MSF_HOST", "127.0.0.1")
    os.environ.setdefault("MSF_PORT", "55553")
    os.environ.setdefault("MSF_PASSWORD", "h4k_msf_rocks")
    if args.sandbox:
        os.environ["H4K_SANDBOX"] = "1"
    if args.data_dir:
        os.environ["H4K_DATA_DIR"] = args.data_dir

    import uvicorn

    if args.no_msf:
        import app_state

        class _NoMsf:
            @property
            def client(self):
                raise RuntimeError("Metasploit disabled (--no-msf)")

            def execute(self, *a, **k):
                return {"error": "Metasploit disabled", "status": "failed"}

            def hosts(self, *a, **k):
                return []

            def services(self, *a, **k):
                return []

            def vulns(self, *a, **k):
                return []

        app_state.msf_client = _NoMsf()

    print(f"[h4k] serving on http://{args.host}:{args.port}")
    print(f"[h4k] api dir: {API_DIR}")
    print(f"[h4k] sandbox: {'on' if args.sandbox else 'off'}")
    uvicorn.run("main:app", host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
