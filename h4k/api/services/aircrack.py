# Aircrack-ng integration: wireless LAN assessment suite.
# For authorized wireless assessments only. Monitor mode, scanning, WPA
# handshake capture/cracking, PMKID and (optional) WPS/rogue-AP helpers.
import logging
import os
import re
import subprocess  # nosec B404 - fixed-argv aircrack-ng wrapper
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.aircrack")

AIRMON = "airmon-ng"
AIRODUMP = "airodump-ng"
AIREPLAY = "aireplay-ng"
AIRCRACK = "aircrack-ng"
AIRBASE = "airbase-ng"


class AircrackService:
    """Aircrack-ng suite wrapper."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.progress = progress or (lambda msg, pct: None)

    def _run(self, argv: list[str], timeout: int = 300) -> dict[str, Any]:
        self.progress(f"[aircrack] {' '.join(argv[:6])}...", 0)
        try:
            proc = subprocess.run(  # nosec B603 - fixed argv, no shell
                argv, capture_output=True, text=True, timeout=timeout, check=False
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
                "stderr": "aircrack-ng not installed",
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

    def check_interfaces(self) -> dict[str, Any]:
        """List wireless interfaces and their driver/chipset."""
        result = self._run([AIRMON])
        interfaces: list[dict[str, Any]] = []
        for line in result["stdout"].split("\n"):
            parts = line.split()
            # Header is "PHY Interface Driver Chipset"; skip it, parse the rest.
            if len(parts) >= 4 and parts[0] != "PHY":
                interfaces.append(
                    {
                        "phy": parts[0],
                        "interface": parts[1],
                        "driver": parts[2],
                        "chipset": " ".join(parts[3:]),
                    }
                )
        return {"interfaces": interfaces, "raw": result["stdout"]}

    def start_monitor(self, interface: str) -> dict[str, Any]:
        """Enable monitor mode on an interface."""
        result = self._run([AIRMON, "start", interface])
        mon_iface: str | None = None
        for line in result["stdout"].split("\n"):
            if "monitor mode enabled" in line.lower():
                match = re.search(r"on\s+(\w+)", line)
                if match:
                    mon_iface = match.group(1)
        return {
            "success": result["success"],
            "monitor_interface": mon_iface,
            "raw": result["stdout"],
        }

    def stop_monitor(self, interface: str) -> dict[str, Any]:
        return self._run([AIRMON, "stop", interface])

    def scan_networks(
        self,
        interface: str,
        duration: int = 30,
        channel: int | None = None,
        output: str | None = None,
    ) -> dict[str, Any]:
        """Scan for wireless networks via airodump-ng."""
        argv = [AIRODUMP, interface, "--write-interval", "1"]
        if channel:
            argv += ["--channel", str(channel)]
        if output:
            argv += ["--write", output, "--output-format", "csv"]

        self.progress(f"scanning on {interface} for {duration}s", 0)
        try:
            proc = subprocess.Popen(  # nosec B603 - fixed argv, no shell
                argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            try:
                proc.wait(timeout=duration)
            except subprocess.TimeoutExpired:
                proc.terminate()
                proc.wait(timeout=5)
            stdout, stderr = proc.communicate()
            raw: dict[str, Any] = {
                "stdout": stdout,
                "stderr": stderr,
                "rc": proc.returncode,
            }
        except FileNotFoundError:
            raw = {"stdout": "", "stderr": "airodump-ng not installed", "rc": -1}
        return {
            "networks": self._parse_csv(f"{output}-01.csv" if output else None),
            "raw": raw,
        }

    @staticmethod
    def _parse_csv(csv_path: str | None) -> list[dict[str, Any]]:
        """Parse airodump-ng CSV output into network records."""
        if not csv_path or not os.path.exists(csv_path):
            return []
        networks: list[dict[str, Any]] = []
        try:
            lines = (
                Path(csv_path)
                .read_text(encoding="utf-8", errors="replace")
                .splitlines()
            )
            headers: list[str] | None = None
            for line in lines:
                if line.startswith("BSSID,"):
                    headers = [h.strip() for h in line.split(",")]
                    continue
                if line.startswith("Station MAC") or not headers:
                    if line.startswith("Station MAC"):
                        break
                    continue
                parts = [p.strip() for p in line.split(",")]
                if len(parts) < len(headers):
                    continue
                net = dict(zip(headers, parts, strict=False))
                networks.append(
                    {
                        "bssid": net.get("BSSID"),
                        "essid": net.get("ESSID"),
                        "channel": net.get("channel"),
                        # airodump-ng labels the encryption column "Privacy".
                        "encryption": net.get("Privacy") or net.get("Encryption"),
                        "cipher": net.get("Cipher"),
                        "auth": net.get("Authentication"),
                        "power": net.get("Power"),
                        "beacons": net.get("Beacons"),
                        "iv": net.get("# IV"),
                    }
                )
        except OSError as exc:  # pragma: no cover - defensive
            logger.debug("CSV parse failed: %s", exc)
        return networks

    def capture_handshake(
        self,
        interface: str,
        bssid: str,
        channel: int,
        output: str,
        duration: int = 60,
        deauth: bool = True,
        deauth_count: int = 10,
    ) -> dict[str, Any]:
        """Capture a WPA/WPA2 4-way handshake (optionally with deauth)."""
        cap_argv = [
            AIRODUMP,
            interface,
            "--bssid",
            bssid,
            "--channel",
            str(channel),
            "--write",
            output,
            "--output-format",
            "pcap",
        ]
        try:
            proc = subprocess.Popen(  # nosec B603 - fixed argv, no shell
                cap_argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except FileNotFoundError:
            return {"handshake_captured": False, "error": "airodump-ng not installed"}

        cap_file = f"{output}-01.cap"
        try:
            if deauth:
                self.progress(f"sending deauth to {bssid}", 10)
                self._run(
                    [AIREPLAY, "--deauth", str(deauth_count), "-a", bssid, interface]
                )
            deadline = time.time() + duration
            while time.time() < deadline:
                if os.path.exists(cap_file):
                    check = self._run([AIRCRACK, cap_file])
                    if "WPA (1 handshake)" in check["stdout"]:
                        return {"handshake_captured": True, "cap_file": cap_file}
                time.sleep(2)
            return {"handshake_captured": False, "cap_file": None}
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def crack_handshake(
        self,
        cap_file: str,
        wordlist: str | None = None,
        bssid: str | None = None,
        essid: str | None = None,
    ) -> dict[str, Any]:
        argv = [AIRCRACK, cap_file]
        if wordlist:
            argv += ["-w", wordlist]
        if bssid:
            argv += ["-b", bssid]
        if essid:
            argv += ["-e", essid]
        return self._run(argv, timeout=3600)

    def crack_pmkid(self, cap_file: str, wordlist: str | None = None) -> dict[str, Any]:
        argv = [AIRCRACK, "-M", cap_file]
        if wordlist:
            argv += ["-w", wordlist]
        return self._run(argv, timeout=3600)

    def create_ap(
        self, interface: str, essid: str, channel: int = 6, hidden: bool = False
    ) -> dict[str, Any]:
        """Create a rogue AP (airbase-ng). Authorized targets only."""
        argv = [AIRBASE, "-e", essid, "-c", str(channel)]
        if hidden:
            argv.append("-H")
        argv.append(interface)
        return self._run(argv, timeout=10)

    def wps_attack(self, interface: str, bssid: str) -> dict[str, Any]:
        """WPS PIN attack via reaver, if present."""
        if not Path("/usr/bin/reaver").exists():
            return {"success": False, "error": "reaver not installed"}
        return self._run(["reaver", "-i", interface, "-b", bssid, "-vv"], timeout=7200)


class AircrackRunner:
    """High-level wireless assessment orchestration."""

    def __init__(self, progress: Callable[[str, float], None] | None = None) -> None:
        self.svc = AircrackService(progress)
        self.progress = progress or (lambda msg, pct: None)

    def full_wpa_assessment(
        self,
        interface: str,
        target_essid: str | None = None,
        wordlist: str | None = None,
        capture_duration: int = 60,
    ) -> dict[str, Any]:
        """Scan -> capture handshakes -> (optionally) crack."""
        results: dict[str, Any] = {
            "interface": interface,
            "networks": [],
            "handshakes": [],
        }

        mon = self.svc.start_monitor(interface)
        if not mon["success"]:
            return {"error": "failed to start monitor mode", "raw": mon.get("raw", "")}
        mon_iface = mon["monitor_interface"] or f"{interface}mon"

        try:
            self.progress("scanning networks", 20)
            scan = self.svc.scan_networks(mon_iface, duration=30)
            networks = scan["networks"]
            results["networks"] = networks

            targets = networks
            if target_essid:
                targets = [n for n in networks if n.get("essid") == target_essid]

            for net in targets[:3]:
                if not str(net.get("encryption", "")).startswith("WPA"):
                    continue
                bssid = str(net.get("bssid", ""))
                self.progress(f"capturing handshake for {net.get('essid')}", 50)
                hs = self.svc.capture_handshake(
                    mon_iface,
                    bssid,
                    int(net.get("channel") or 1),
                    f"/tmp/hs_{bssid.replace(':', '')}",  # nosec B108 - artifact
                    duration=capture_duration,
                    deauth=True,
                )
                handshake = {"essid": net.get("essid"), "bssid": bssid, **hs}
                if wordlist and hs.get("handshake_captured"):
                    self.progress("cracking handshake", 80)
                    handshake["crack_result"] = self.svc.crack_handshake(
                        hs["cap_file"], wordlist, bssid, net.get("essid")
                    )
                results["handshakes"].append(handshake)
        finally:
            self.svc.stop_monitor(mon_iface)
        return results


def _as_text(data: str | bytes | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return data
