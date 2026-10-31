# Fire TV / Android TV assessment: ADB + recon for the authorised-TV use case.
# All actions are explicit opt-in endpoints; a scan never touches a TV.
# Detection (recon/mdns_discover) is read-only. State-changing calls
# (shell/install/push/keyevent) are disabled in sandbox mode.
import json
import logging
import re
import shlex
import shutil
import socket
import struct
import subprocess  # nosec B404 - fixed-argv adb wrapper
import time
import urllib.request
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.firetv")

ADB = "adb"
DEFAULT_PORT = 5555

# Ports worth probing on a Fire TV: ADB, DIAL/HTTP, Cast, AirPlay.
TV_PORTS = (5555, 8008, 8009, 7000, 6466, 6467)

# Keyevent allowlist: Android KEYCODE_* names (without the prefix) plus the
# numeric range. Anything else is rejected before adb ever runs.
KEY_NAMES = frozenset(
    {
        "HOME",
        "BACK",
        "DPAD_UP",
        "DPAD_DOWN",
        "DPAD_LEFT",
        "DPAD_RIGHT",
        "DPAD_CENTER",
        "MENU",
        "SEARCH",
        "VOLUME_UP",
        "VOLUME_DOWN",
        "VOLUME_MUTE",
        "POWER",
        "SLEEP",
        "WAKEUP",
        "MEDIA_PLAY",
        "MEDIA_PAUSE",
        "MEDIA_PLAY_PAUSE",
        "MEDIA_STOP",
        "MEDIA_NEXT",
        "MEDIA_PREVIOUS",
        "MEDIA_REWIND",
        "MEDIA_FAST_FORWARD",
        "TV",
        "GUIDE",
        "INFO",
        "SETTINGS",
        "ENTER",
        "DEL",
        "TAB",
        "ESCAPE",
        "CAPTIONS",
        "STAR",
        "POUND",
    }
)


def _target_addr(target: str, port: int = DEFAULT_PORT) -> str:
    """Normalise to host:port. Rejects adb-flag injection ("-x")."""
    target = (target or "").strip()
    if not target or target.startswith("-"):
        raise ValueError("invalid target")
    if ":" in target:
        host, _, maybe_port = target.rpartition(":")
        if host and maybe_port.isdigit():
            return f"{host}:{maybe_port}"
        # IPv6 or trailing colon: keep adb's own parsing, but never a flag
        return target
    return f"{target}:{port}"


class FireTVService:
    """ADB + recon wrapper for Fire TV / Android TV targets."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)

    # -- plumbing -------------------------------------------------------
    def _run(self, argv: list[str], timeout: int = 60) -> dict[str, Any]:
        self.progress(f"[firetv] {' '.join(argv[:6])}...", 0)
        try:
            proc = subprocess.run(  # nosec B603 - fixed argv, no shell
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return {
                "stdout": proc.stdout or "",
                "stderr": proc.stderr or "",
                "rc": proc.returncode,
                "success": proc.returncode == 0,
                "timed_out": False,
            }
        except subprocess.TimeoutExpired as exc:
            return {
                "stdout": _as_text(exc.stdout),
                "stderr": _as_text(exc.stderr),
                "rc": None,
                "success": False,
                "timed_out": True,
            }
        except FileNotFoundError:
            return {
                "stdout": "",
                "stderr": "adb not installed",
                "rc": -1,
                "success": False,
                "timed_out": False,
            }
        except Exception as exc:  # pragma: no cover - defensive
            return {
                "stdout": "",
                "stderr": str(exc),
                "rc": -1,
                "success": False,
                "timed_out": False,
            }

    def _adb(self, addr: str, *args: str, timeout: int = 60) -> dict[str, Any]:
        if shutil.which(ADB) is None:
            return {
                "stdout": "",
                "stderr": "adb not installed",
                "rc": -1,
                "success": False,
                "timed_out": False,
            }
        return self._run([ADB, "-s", addr, *args], timeout=timeout)

    @staticmethod
    def _mutating_ok() -> tuple[bool, str]:
        from services.sandbox import enabled as sandbox_enabled

        if sandbox_enabled():
            return False, "disabled in sandbox mode"
        return True, ""

    # -- connection -----------------------------------------------------
    def check(self) -> dict[str, Any]:
        """Is the adb client installed and what version is it?"""
        if shutil.which(ADB) is None:
            return {"installed": False, "version": None}
        out = self._run([ADB, "version"], timeout=10)
        first = (out["stdout"] or "").strip().splitlines()
        return {
            "installed": True,
            "version": first[0][:120] if first else "unknown",
        }

    def connect(self, target: str, port: int = DEFAULT_PORT) -> dict[str, Any]:
        """`adb connect`: asks the TV to show the pairing prompt (harmless)."""
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        out = self._run([ADB, "connect", addr], timeout=30)
        text = (out["stdout"] + out["stderr"]).lower()
        connected = "connected" in text and "failed" not in text
        unauthorized = "unauthorized" in text
        return {
            "success": connected,
            "addr": addr,
            "unauthorized": unauthorized,
            "needs_on_screen_approval": unauthorized or not connected,
            "stdout": out["stdout"][:2000],
            "stderr": out["stderr"][:500],
        }

    def disconnect(self, target: str, port: int = DEFAULT_PORT) -> dict[str, Any]:
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        out = self._run([ADB, "disconnect", addr], timeout=15)
        return {"success": out["success"], "addr": addr}

    def state(self, target: str, port: int = DEFAULT_PORT) -> dict[str, Any]:
        """device | unauthorized | offline — authorisation without a shell."""
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        out = self._run([ADB, "devices"], timeout=15)
        state = "unknown"
        for line in (out["stdout"] or "").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == addr:
                state = parts[1]
        if state == "unknown":
            probe = self._adb(addr, "get-state", timeout=15)
            text = (probe["stdout"] or "").strip().lower()
            err = (probe["stderr"] or "").lower()
            # get-state prints exactly "device" on success; a miss says
            # "error: device '<addr>' not found" -- match exactly, not
            # substring, or every miss reads as authorised.
            if text == "device":
                state = "device"
            elif "unauthorized" in text or "unauthorized" in err:
                state = "unauthorized"
            elif "offline" in text or "offline" in err:
                state = "offline"
        return {"success": True, "addr": addr, "state": state}

    # -- read-only interrogation ----------------------------------------
    def apps(self, target: str, port: int = DEFAULT_PORT) -> dict[str, Any]:
        """Installed packages (`pm list packages -f`) + focus window."""
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        out = self._adb(addr, "shell", "pm", "list", "packages", "-f", timeout=60)
        packages: list[dict[str, str]] = []
        for line in (out["stdout"] or "").splitlines():
            line = line.strip()
            if line.startswith("package:"):
                body = line[len("package:") :]
                apk, _, name = body.rpartition("=")
                packages.append({"package": name or body, "apk": apk})
        focus = self._adb(addr, "shell", "dumpsys", "window", timeout=30)
        current: str | None = None
        for line in (focus["stdout"] or "").splitlines():
            if "mCurrentFocus" in line or "mFocusedApp" in line:
                current = line.strip()[:200]
                break
        return {
            "success": out["success"],
            "addr": addr,
            "count": len(packages),
            "packages": packages,
            "current_focus": current,
        }

    def screenshot(
        self, target: str, port: int = DEFAULT_PORT, out_dir: str | None = None
    ) -> dict[str, Any]:
        """Grab the current framebuffer via `screencap` (read-only)."""
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        if shutil.which(ADB) is None:
            return {"success": False, "error": "adb not installed"}
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        host = addr.replace(":", "_")
        directory = Path(out_dir) if out_dir else _artifact_dir()
        try:
            directory.mkdir(parents=True, exist_ok=True)
            dest = directory / f"firetv-{host}-{stamp}.png"
            proc = subprocess.run(  # nosec B603 - fixed argv, no shell
                [ADB, "-s", addr, "exec-out", "screencap", "-p"],
                capture_output=True,
                timeout=60,
                check=False,
            )
        except FileNotFoundError:
            return {"success": False, "error": "adb not installed"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "screencap timed out"}
        data = proc.stdout or b""
        # screencap -p emits a PNG; a stub/error reply is far too small
        if proc.returncode != 0 or len(data) < 100 or not data.startswith(b"\x89PNG"):
            err = (proc.stderr or b"").decode("utf-8", "replace")[:300]
            return {"success": False, "error": err or "screencap failed"}
        dest.write_bytes(data)
        return {"success": True, "addr": addr, "file": str(dest), "bytes": len(data)}

    def logcat(
        self, target: str, port: int = DEFAULT_PORT, lines: int = 200
    ) -> dict[str, Any]:
        """Recent logcat (`-d -t N`): no streaming, bounded output."""
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        out = self._adb(
            addr, "logcat", "-d", "-t", str(max(1, min(lines, 5000))), timeout=60
        )
        text = out["stdout"][:20000]
        return {
            "success": out["success"],
            "addr": addr,
            "lines": text.splitlines()[-min(lines, 200) :],
            "truncated": len(out["stdout"]) > 20000,
        }

    def pull(
        self,
        target: str,
        remote: str,
        local: str | None = None,
        port: int = DEFAULT_PORT,
    ) -> dict[str, Any]:
        """`adb pull` into the h4k data dir (APK backup, configs)."""
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        if not remote or remote.startswith("-"):
            return {"success": False, "error": "invalid remote path"}
        dest = _artifact_dir() / Path(local or "pull").name
        out = self._adb(addr, "pull", remote, str(dest), timeout=300)
        return {
            "success": out["success"] and dest.exists(),
            "addr": addr,
            "remote": remote,
            "file": str(dest) if dest.exists() else None,
            "stdout": out["stdout"][:1000],
            "stderr": out["stderr"][:500],
        }

    # -- state-changing (sandbox-gated) ----------------------------------
    def shell(
        self, target: str, command: str, port: int = DEFAULT_PORT
    ) -> dict[str, Any]:
        """Run a shell command as the adb `shell` user (never root-claimed)."""
        ok, reason = self._mutating_ok()
        if not ok:
            return {"success": False, "error": reason}
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        if not (command or "").strip():
            return {"success": False, "error": "empty command"}
        # shlex, not a shell: the list goes straight to exec, no expansion.
        out = self._adb(addr, "shell", *shlex.split(command), timeout=120)
        return {
            "success": out["success"],
            "addr": addr,
            "command": command[:300],
            "stdout": out["stdout"][:20000],
            "stderr": out["stderr"][:2000],
            "rc": out["rc"],
        }

    def keyevent(
        self, target: str, key: str, port: int = DEFAULT_PORT
    ) -> dict[str, Any]:
        """Press a remote key (DPAD_*/HOME/BACK/... or numeric 0-255)."""
        ok, reason = self._mutating_ok()
        if not ok:
            return {"success": False, "error": reason}
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        code = (key or "").strip().upper()
        if not ((code.isdigit() and 0 <= int(code) <= 255) or code in KEY_NAMES):
            return {"success": False, "error": f"rejected key: {key!r:.40}"}
        out = self._adb(addr, "shell", "input", "keyevent", code, timeout=30)
        return {"success": out["success"], "addr": addr, "key": code}

    def install(
        self, target: str, apk: str, port: int = DEFAULT_PORT
    ) -> dict[str, Any]:
        """`adb install` a local APK (operator-supplied file only)."""
        ok, reason = self._mutating_ok()
        if not ok:
            return {"success": False, "error": reason}
        try:
            addr = _target_addr(target, port)
        except ValueError as exc:
            return {"success": False, "error": str(exc)}
        if not apk or not Path(apk).is_file():
            return {"success": False, "error": "apk file not found"}
        out = self._adb(addr, "install", "-r", apk, timeout=300)
        text = (out["stdout"] + out["stderr"])[:1000]
        return {"success": "success" in text.lower(), "addr": addr, "output": text}

    # -- recon ------------------------------------------------------------
    def recon(self, target: str) -> dict[str, Any]:
        """Read-only Fire TV fingerprint: ports + eureka + adb state."""
        host = (target or "").strip().split(":")[0]
        if not host or host.startswith("-"):
            return {"success": False, "error": "invalid target"}
        ports: dict[int, bool] = {}
        for p in TV_PORTS:
            try:
                with socket.create_connection((host, p), timeout=3):
                    ports[p] = True
            except OSError:
                ports[p] = False
        eureka: dict[str, Any] = {}
        if ports.get(8008):
            try:
                url = f"http://{host}:8008/setup/eureka_info?params=name,model_name,manufacturer,build_name"  # nosec B310 - target host only
                with urllib.request.urlopen(url, timeout=8) as resp:  # nosec B310
                    eureka = json.loads(resp.read().decode() or "{}")
            except Exception as exc:
                eureka = {"error": str(exc)[:200]}
        adb_state = self.state(host)
        return {
            "success": True,
            "target": host,
            "ports": ports,
            "eureka": eureka,
            "adb_state": adb_state.get("state", "unknown"),
            "looks_like_fire_tv": bool(ports.get(5555) or ports.get(8009))
            or "amazon" in json.dumps(eureka).lower(),
        }


def mdns_discover(
    timeout: float = 8.0, queries: list[str] | None = None
) -> dict[str, Any]:
    """Listen for Fire TV mDNS announcements (pure stdlib, no root needed).

    Asks for _amzn-wplay / _airplay / _alexa and parses the instance names
    (`n=`) and `model=` tokens out of the replies, keyed by source IP.
    Best-effort: binary DNS is decoded lossy and matched with regexes.
    """
    names = queries or [
        "_amzn-wplay._tcp.local",
        "_airplay._tcp.local",
        "_alexa._tcp.local",
    ]
    found: dict[str, dict[str, Any]] = {}

    def _q(name: str) -> bytes:
        hdr = struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0)
        qn = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
        return hdr + qn + struct.pack(">HH", 12, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", 5353))
        except OSError as exc:
            return {"success": False, "error": f"bind failed: {exc}", "devices": []}
        try:
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_ADD_MEMBERSHIP,
                struct.pack(
                    "4s4s", socket.inet_aton("224.0.0.251"), socket.inet_aton("0.0.0.0")
                ),
            )
        except OSError as exc:
            return {
                "success": False,
                "error": f"multicast failed: {exc}",
                "devices": [],
            }
        sock.settimeout(2.0)
        for name in names:
            with suppress(OSError):
                sock.sendto(_q(name), ("224.0.0.251", 5353))
            time.sleep(0.2)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(9000)
            except TimeoutError:
                continue
            except OSError:
                break
            ip = addr[0]
            blob = data.decode("utf-8", "replace")
            entry = found.setdefault(ip, {"ip": ip, "names": [], "models": []})
            for m in re.finditer(r"n=([^ \x00-\x1f\x7f]{1,80})", blob):
                name = m.group(1).strip(" |")
                if name and name not in entry["names"]:
                    entry["names"].append(name)
            for m in re.finditer(r"model=([A-Za-z0-9_.\-]{1,40})", blob):
                model = m.group(1)
                if model not in entry["models"]:
                    entry["models"].append(model)
    finally:
        sock.close()
    return {"success": True, "devices": sorted(found.values(), key=lambda d: d["ip"])}


# -- module-level helpers (match the ad_tools/john style) ----------------


def firetv_recon(target: str) -> dict[str, Any]:
    return FireTVService().recon(target)


def firetv_connect(target: str, port: int = DEFAULT_PORT) -> dict[str, Any]:
    return FireTVService().connect(target, port)


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data


def _artifact_dir() -> Path:
    from paths import data_dir

    path = data_dir() / "firetv"
    with suppress(OSError):
        path.mkdir(parents=True, exist_ok=True)
    return path
