# Network-layer lab tooling (all OPT-IN, lab-only): local sniffing with tcpdump,
# ARP discovery, bettercap MITM, and WiFi capture/cracking via aircrack-ng.
#
# These capabilities are for authorized lab use on networks you control. They may
# interact with low-level/NL80211 interfaces that require a monitor-mode NIC and
# root; every call is best-effort and returns a structured "not supported" if the
# environment can't do it. Nothing here is pointed at third-party traffic by us —
# the operator is expected to attach the right interface/lab scope.
import logging
import shutil
import subprocess  # nosec B404 - runs tcpdump/airmon/bettercap for lab sniffing
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.net")

OUT_DIR = Path("/var/lib/h4k/captures")


def _which(t: str) -> str | None:
    return shutil.which(t)


def _ensure_out_dir() -> Path:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUT_DIR


def _run(cmd: list[str], timeout: int = 120) -> dict[str, Any]:
    try:
        proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "rc": proc.returncode,
            "stdout": (proc.stdout or "")[-4000:],
            "stderr": (proc.stderr or "")[-2000:],
        }
    except FileNotFoundError:
        return {"rc": -1, "stdout": "", "stderr": f"{cmd[0]} not installed"}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": "timed out"}
    except Exception as exc:  # pragma: no cover - defensive
        return {"rc": -1, "stdout": "", "stderr": str(exc)}


def detect_interfaces() -> list[dict[str, Any]]:
    """Best-effort list of network interfaces (from /proc/net/dev + ip)."""
    interfaces: list[dict[str, Any]] = []
    # ip -o link
    if _which("ip"):
        r = _run(["ip", "-o", "link", "show"], timeout=10)
        for line in (r.get("stdout") or "").splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                name = parts[1].strip()
                interfaces.append({"name": name, "type": "link"})
    return interfaces


def sniff_packets(interface: str, count: int = 20, timeout: int = 15) -> dict[str, Any]:
    """Capture a few packets on an interface with tcpdump (opt-in, lab)."""
    tcpdump = _which("tcpdump")
    if not tcpdump:
        return {"ok": False, "error": "tcpdump not installed"}
    cmd = [
        tcpdump,
        "-i",
        interface,
        "-c",
        str(count),
        "-nn",
        "-tttt",
        "-l",
    ]
    r = _run(cmd, timeout=timeout)
    r["ok"] = r.get("rc") in (0, 1, 124)  # 1 = no packets/EOF, 124=timeout
    return r


def arp_who(interface: str, count: int = 8, timeout: int = 15) -> dict[str, Any]:
    """Trigger an ARP 'who-has' sweep via tcpdump/arp-scan on an interface."""
    arp = _which("arp-scan")
    if arp:
        r = _run([arp, "-I", interface, "-localnet", "-r", str(count)], timeout=timeout)
        r["ok"] = r.get("rc") in (0, 1)
        return r
    # fallback: ping sweep then read arp cache
    return {
        "ok": False,
        "error": "arp-scan not installed",
        "hint": "use /api/neighbors for an ARP sweep",
    }


def mitm_arp_poison(interface: str, target: str, seconds: int = 20) -> dict[str, Any]:
    """Run a short bettercap ARP-spoof demo on a lab interface (opt-in).

    Bettercap normally runs interactively; we start it bound to a single target
    and stop it after `seconds`. This is for sanctioned labs only.
    """
    bettercap = _which("bettercap")
    if not bettercap:
        return {"ok": False, "error": "bettercap not installed"}
    if not target:
        return {"ok": False, "error": "target IP required"}
    # bettercap: -iface, no-http-server, only enable the arp.spoof module
    cmd = [
        bettercap,
        "-iface",
        interface,
        "-no-http-server",
        "-no-https-server",
        "-eval",
        "set arp.spoof.targets "
        + target
        + "; arp.spoof on; sleep "
        + str(seconds)
        + "; arp.spoof off; quit",
    ]
    r = _run(cmd, timeout=seconds + 15)
    r["ok"] = True
    return r


def wifi_scan(interface: str, timeout: int = 20) -> dict[str, Any]:
    """List nearby APs using airdump-ng via a monitor-capable interface."""
    airdump = _which("airmon-ng")
    if not airdump:
        return {"ok": False, "error": "airmon-ng not installed"}
    # put interface in monitor mode (best-effort), then airdump-ng for a moment
    _run([airdump, "start", interface, "mon"], timeout=15)
    dump = _which("airodump-ng")
    if not dump:
        _run([airdump, "stop", interface + "mon"], timeout=15)
        return {"ok": False, "error": "airodump-ng not installed"}
    out = _ensure_out_dir() / "wifi-scan"
    r = _run([dump, "-j", str(out), interface + "mon"], timeout=timeout)
    _run([airdump, "stop", interface + "mon"], timeout=15)
    # airodump-ng -j writes wifi-scan-01.json
    json_file = out.with_name(f"{out.name}-01.json")
    if not r.get("ok", True):
        r["files"] = []
        return r
    r["files"] = [str(json_file)] if json_file.exists() else []
    return r


def wifi_capture(
    interface: str, seconds: int = 20, channel: str = "6"
) -> dict[str, Any]:
    """Capture raw frames (for offline cracking) with airodump-ng."""
    dump = _which("airodump-ng")
    if not dump:
        return {"ok": False, "error": "airodump-ng not installed"}
    out = _ensure_out_dir() / "capture"
    cmd = [
        dump,
        "-c",
        channel,
        "--bssid",
        "00:00:00:00:00:00",
        "-w",
        str(out),
        interface,
    ]
    # run briefly then we can't easily stop; instead use a short sleep wrapper
    r = _run(["timeout", str(seconds), *cmd], timeout=seconds + 15)
    r["ok"] = True
    r["files"] = [
        str(p)
        for p in OUT_DIR.glob("capture*")
        if p.suffix in (".cap", ".pcap", ".pcapng")
    ]
    return r
