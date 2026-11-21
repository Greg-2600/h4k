#!/usr/bin/env python3
"""h4k sandbox runner sidecar.

A tiny, dependency-free HTTP executor that runs an allowlisted tool inside a
resource envelope and returns the captured output. It exists so the API
container can hand aggressive tooling to a separate container with its own
limits, without giving the API a shell.

Run:
    H4K_SANDBOX_TOKEN=change-me python3 runner.py
    curl -s localhost:9099/health
    curl -s localhost:9099/run -H 'X-Sandbox-Token: change-me' \
      -H 'Content-Type: application/json' \
      -d '{"profile":"recon","argv":["nmap","-sT","-p22","127.0.0.1"],"timeout_s":30}'
"""
from __future__ import annotations

import json
import os
import resource
import shutil
import signal
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

PORT = int(os.environ.get("H4K_SANDBOX_PORT", "9099"))
TOKEN = os.environ.get("H4K_SANDBOX_TOKEN", "")
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_OUTPUT_KB = 512

PROFILES: dict[str, dict[str, Any]] = {
    "recon": {
        "tools": ["nmap", "masscan", "arp-scan", "dig", "host", "nslookup", "traceroute"],
        "cpu_seconds": 180,
        "memory_mb": 768,
        "processes": 64,
        "file_mb": 32,
        "runtime_s": 600,
    },
    "web": {
        "tools": ["nikto", "nikto.pl", "nuclei", "ffuf", "gobuster", "sqlmap", "whatweb", "zap", "zap.sh", "curl"],
        "cpu_seconds": 240,
        "memory_mb": 1024,
        "processes": 96,
        "file_mb": 128,
        "runtime_s": 900,
    },
    "creds": {
        "tools": ["hydra", "ncrack", "john", "hashcat", "smbclient", "rpcclient"],
        "cpu_seconds": 300,
        "memory_mb": 768,
        "processes": 32,
        "file_mb": 32,
        "runtime_s": 600,
    },
    "ad": {
        "tools": ["ldapsearch", "ldapwhoami", "rpcclient", "smbclient", "nmap", "bloodhound-python", "GetNPUsers.py", "GetUserSPNs.py", "python3"],
        "cpu_seconds": 180,
        "memory_mb": 1024,
        "processes": 48,
        "file_mb": 256,
        "runtime_s": 900,
    },
    "lab": {
        "tools": ["python3", "curl", "dig", "mosquitto_pub", "mosquitto_sub"],
        "cpu_seconds": 60,
        "memory_mb": 256,
        "processes": 16,
        "file_mb": 8,
        "runtime_s": 120,
    },
}
PROFILES["full"] = {
    "tools": sorted({tool for p in PROFILES.values() for tool in p["tools"]}),
    **PROFILES["recon"],
    "cpu_seconds": 600,
    "memory_mb": 4096,
    "processes": 256,
    "file_mb": 1024,
    "runtime_s": 3600,
}


class RunnerError(Exception):
    pass


def _limits(profile: dict[str, Any]) -> list[tuple[int, int, int]]:
    mb = 1024 * 1024
    return [
        (resource.RLIMIT_CPU, profile["cpu_seconds"], profile["cpu_seconds"] + 5),
        (resource.RLIMIT_AS, profile["memory_mb"] * mb, profile["memory_mb"] * mb),
        (resource.RLIMIT_NPROC, profile["processes"], profile["processes"]),
        (resource.RLIMIT_FSIZE, profile["file_mb"] * mb, profile["file_mb"] * mb),
        (resource.RLIMIT_CORE, 0, 0),
        (resource.RLIMIT_NOFILE, 256, 256),
    ]


def _preexec(profile: dict[str, Any]):
    limits = _limits(profile)

    def _apply() -> None:
        for rid, soft, hard in limits:
            try:
                resource.setrlimit(rid, (soft, hard))
            except (ValueError, OSError):
                pass

    return _apply


def _truncate(text: str) -> tuple[str, bool]:
    limit = MAX_OUTPUT_KB * 1024
    return (text, False) if len(text) <= limit else (text[:limit] + "\n…[truncated]…", True)


def run(profile_name: str, argv: list[str], timeout_s: float, stdin: str, env: dict[str, str]) -> dict[str, Any]:
    profile = PROFILES.get(profile_name)
    if profile is None:
        raise RunnerError(f"unknown profile: {profile_name}")
    if not argv:
        raise RunnerError("argv is required")
    tool = os.path.basename(str(argv[0]))
    if tool not in profile["tools"]:
        raise RunnerError(f"{tool!r} is not allowed by profile {profile_name}")
    if any("\x00" in str(a) or "\n" in str(a) for a in argv):
        raise RunnerError("argv contains a control character")
    budget = min(max(0.5, float(timeout_s)), float(profile["runtime_s"]))
    workdir = tempfile.mkdtemp(prefix=f"h4k-{profile_name}-")
    child_env = {
        "PATH": SAFE_PATH,
        "HOME": workdir,
        "TMPDIR": workdir,
        "LANG": "C.UTF-8",
        "TERM": "dumb",
    }
    for key, value in env.items():
        if key.startswith("H4K_") or key in {"LC_ALL", "TZ"}:
            child_env[key] = str(value)
    started = time.monotonic()
    try:
        proc = subprocess.Popen(
            [str(a) for a in argv],
            cwd=workdir,
            env=child_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=_preexec(profile),
            start_new_session=True,
        )
        timed_out = False
        try:
            out, err = proc.communicate(input=stdin, timeout=budget)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                proc.kill()
            out, err = proc.communicate(timeout=5)
        stdout, t1 = _truncate(out or "")
        stderr, t2 = _truncate(err or "")
        return {
            "ok": proc.returncode == 0 and not timed_out,
            "rc": proc.returncode,
            "tool": tool,
            "profile": profile_name,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": timed_out,
            "truncated": t1 or t2,
            "duration_s": round(time.monotonic() - started, 3),
            "limits": {
                "cpu_seconds": profile["cpu_seconds"],
                "memory_mb": profile["memory_mb"],
                "processes": profile["processes"],
                "file_mb": profile["file_mb"],
                "runtime_s": budget,
            },
            "mode": "sidecar",
        }
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


class Handler(BaseHTTPRequestHandler):
    server_version = "h4k-sandbox/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        print(f"[sandbox] {self.address_string()} {fmt % args}", flush=True)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json(200, {"status": "ok", "profiles": sorted(PROFILES)})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/run":
            self._json(404, {"error": "not found"})
            return
        if not TOKEN:
            self._json(503, {"error": "H4K_SANDBOX_TOKEN is not configured"})
            return
        if self.headers.get("X-Sandbox-Token") != TOKEN:
            self._json(401, {"error": "bad sandbox token"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_000_000:
                raise RunnerError("invalid body length")
            body = json.loads(self.rfile.read(length).decode())
            result = run(
                str(body.get("profile") or ""),
                list(body.get("argv") or []),
                float(body.get("timeout_s") or 60),
                str(body.get("stdin") or ""),
                dict(body.get("env") or {}),
            )
        except (RunnerError, ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
            return
        except Exception as exc:  # pragma: no cover - defensive
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})
            return
        self._json(200, result)


def main() -> None:
    if not TOKEN:
        print("[sandbox] WARNING: H4K_SANDBOX_TOKEN is empty; refusing unauthenticated runs", flush=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[sandbox] listening on 0.0.0.0:{PORT}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
