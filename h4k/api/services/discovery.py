# Local-network neighbor discovery using ARP (arp-scan / arp cache / tcpdump)
# and Metasploit's arp_sweep auxiliary module.
import logging
import re
import subprocess  # nosec B404 - drives arp-scan / arp host utilities
from typing import Any

from schemas import Neighbor
from services.msfrpc import MsfClient

logger = logging.getLogger("h4k.discovery")

MAC_OUI: dict[str, str] = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "52:54:00": "QEMU/KVM",
    "08:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1a:4a": "Apple",
    "00:03:93": "Apple",
    "00:1b:44": "Cisco",
    "00:17:c8": "Cisco",
    "cc:32:e5": "MikroTik",
    "00:1b:21": "Intel",
    "f8:ca:b8": "Netgear",
    "ec:08:6b": "Netgear",
}


def _oui_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = mac.replace(":", "").lower()
    for oui, vendor in MAC_OUI.items():
        if prefix.startswith(oui.replace(":", "").lower()):
            return vendor
    return None


class NeighborFinder:
    def __init__(self, msf: MsfClient):
        self.msf = msf

    def discover(self, target_cidr: str) -> list[Neighbor]:
        """Combine an arp sweep (arp-scan / arp cache / msf arp_sweep)."""
        found: dict[str, Neighbor] = {}

        # 1. Metasploit arp_sweep (broad, may need privileged net stack).
        try:
            self.msf.execute(
                "auxiliary",
                "auxiliary/scanner/discovery/arp_sweep",
                {"RHOSTS": target_cidr},
            )
        except Exception as exc:
            logger.warning("arp_sweep failed: %s", exc)

        # 2. arp-scan if installed (fast, gives MAC + vendor).
        for entry in self._arp_scan(target_cidr):
            found[entry.ip] = entry

        # 3. local ARP cache as a fallback.
        for entry in self._arp_cache():
            found.setdefault(entry.ip, entry)

        return list(found.values())

    def _arp_scan(self, target: str) -> list[Neighbor]:
        out: list[Neighbor] = []
        # target is a bare argv element (no shell interpolation); binary path is
        # literal. Guarded against missing binary by FileNotFoundError handling.
        proc = subprocess.run(  # nosec B603 B607 - fixed binary, argv element
            ["arp-scan", "--interface=eth0", target],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        for line in (proc.stdout or "").splitlines():
            m = re.match(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+.*?(\w[\w ]*)?", line
            )
            if m:
                ip, mac, host = m.groups()
                out.append(
                    Neighbor(
                        ip=ip,
                        mac=mac,
                        vendor=_oui_vendor(mac) or None,
                        hostname=(host or None),
                    )
                )
        return out

    @staticmethod
    def _arp_cache() -> list[Neighbor]:
        out: list[Neighbor] = []
        try:
            proc = subprocess.run(  # nosec B603 B607 - fixed binary, no input
                ["arp", "-a"], capture_output=True, text=True, timeout=20, check=False
            )
        except FileNotFoundError:
            return out
        for line in (proc.stdout or "").splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)", line)
            if m:
                ip, mac = m.groups()
                out.append(Neighbor(ip=ip, mac=mac, vendor=_oui_vendor(mac) or None))
        return out

    @staticmethod
    def neighbors_to_dicts(neighbors: list[Neighbor]) -> list[dict[str, Any]]:
        return [n.model_dump(exclude_none=True) for n in neighbors]
