#!/usr/bin/env python3
"""h4k endpoint telemetry agent.

Tails one or more JSON-lines log files (sysmon-forwarded, auditd JSON, osquery,
zeek) and ships batches to h4k's `/api/telemetry/events`. Single file, stdlib
only, read-only on the host, bounded batch size and retry with backoff.

Config (env):
  H4K_URL            http://127.0.0.1:3137
  H4K_API_KEY        optional API key when auth is enabled
  H4K_AGENT_FILES    /var/log/h4k/events.jsonl,/var/log/audit/audit.json
  H4K_AGENT_SOURCE   agent
  H4K_AGENT_FROM_START  1 to read existing lines (default 0 = only new lines)
  H4K_AGENT_SYNTHETIC   1 to emit a demo event every interval
  H4K_AGENT_INTERVAL    seconds between flushes (default 2)
  H4K_AGENT_ONCE        1 to send the current backlog and exit
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

URL = os.environ.get("H4K_URL", "http://127.0.0.1:3137").rstrip("/")
API_KEY = os.environ.get("H4K_API_KEY", "")
SOURCE = os.environ.get("H4K_AGENT_SOURCE", "agent")
FILES = [p.strip() for p in os.environ.get("H4K_AGENT_FILES", "").split(",") if p.strip()]
FROM_START = os.environ.get("H4K_AGENT_FROM_START", "0") == "1"
SYNTHETIC = os.environ.get("H4K_AGENT_SYNTHETIC", "0") == "1"
INTERVAL = float(os.environ.get("H4K_AGENT_INTERVAL", "2"))
ONCE = os.environ.get("H4K_AGENT_ONCE", "0") == "1"
BATCH = 50


def log(message: str) -> None:
    print(f"[telemetry-agent] {message}", flush=True)


def _headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    return headers


def send(events: list[dict[str, Any]]) -> bool:
    if not events:
        return True
    payload = json.dumps({"source": SOURCE, "events": events}).encode()
    req = urllib.request.Request(
        f"{URL}/api/telemetry/events", data=payload, headers=_headers(), method="POST"
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
                body = json.loads(resp.read().decode() or "{}")
            log(
                f"sent {len(events)} event(s): accepted={body.get('accepted')} "
                f"detections={body.get('detection_count')}"
            )
            return True
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            wait = 2**attempt
            log(f"send failed ({exc}); retrying in {wait}s")
            time.sleep(wait)
    return False


def parse_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        value = json.loads(line)
    except ValueError:
        return {"message": line, "source": SOURCE}
    if isinstance(value, dict):
        return value
    return {"message": line, "source": SOURCE}


def read_file(path: Path, offset: int) -> tuple[list[dict[str, Any]], int, bool]:
    """Read new complete lines; return (events, new_offset, rotated)."""
    try:
        stat = path.stat()
    except OSError:
        return [], offset, True
    if stat.st_size < offset:
        offset = 0  # truncated/rotated
    events: list[dict[str, Any]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            while True:
                line = fh.readline()
                if not line:
                    break
                if not line.endswith("\n"):
                    # partial line: wait for the writer to finish
                    break
                event = parse_line(line)
                if event:
                    events.append(event)
                offset += len(line.encode("utf-8"))
    except OSError as exc:
        log(f"read failed for {path}: {exc}")
    return events, offset, False


def synthetic(seq: int) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat(timespec="seconds")
    samples = [
        {
            "source": "sysmon",
            "event_id": "1",
            "message": "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA",
        },
        {
            "source": "security",
            "event_id": "4769",
            "message": "Kerberos service ticket requested, encryption type 0x17 (RC4)",
        },
        {
            "source": "sysmon",
            "event_id": "10",
            "message": "procdump.exe accessed lsass.exe memory",
        },
        {
            "source": "ot",
            "event_id": "modbus",
            "message": "modbus fc=16 write multiple registers unit=1",
        },
    ]
    sample = dict(samples[seq % len(samples)])
    return {"ts": now, "host": "iotlab-agent", "event_uid": f"agent-{seq}", **sample}


def main() -> int:
    if not FILES and not SYNTHETIC and not ONCE:
        log("no H4K_AGENT_FILES and synthetic mode off; nothing to do")
        return 2
    offsets: dict[str, int] = {}
    for name in FILES:
        path = Path(name)
        try:
            offsets[name] = 0 if FROM_START else path.stat().st_size
        except OSError:
            offsets[name] = 0
    log(f"watching {len(FILES)} file(s) -> {URL}; synthetic={SYNTHETIC}")
    seq = 0
    pending: list[dict[str, Any]] = []
    while True:
        for name in FILES:
            events, offset, rotated = read_file(Path(name), offsets[name])
            offsets[name] = offset
            if rotated:
                log(f"{name} rotated/truncated; offset reset")
            pending.extend(events)
        if SYNTHETIC and (not pending or random.random() < 0.5):
            pending.append(synthetic(seq))
            seq += 1
        while len(pending) >= BATCH:
            send(pending[:BATCH])
            pending = pending[BATCH:]
        if pending:
            send(pending)
            pending = []
        if ONCE:
            return 0
        time.sleep(max(0.5, INTERVAL))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
