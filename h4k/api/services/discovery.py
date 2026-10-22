# Local-network neighbor discovery using ARP (arp-scan / arp cache / tcpdump)
# and Metasploit's arp_sweep auxiliary module, plus IPv6 and SNMP discovery.
import logging
import os
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
    "e4:5f:01": "Raspberry Pi",
    "00:1a:4a": "Apple",
    "00:03:93": "Apple",
    "00:1b:44": "Cisco",
    "00:17:c8": "Cisco",
    "cc:32:e5": "MikroTik",
    "64:d1:54": "MikroTik",
    "00:1b:21": "Intel",
    "f8:ca:b8": "Netgear",
    "ec:08:6b": "Netgear",
    "9c:d3:6d": "Netgear",
    "04:a1:51": "TP-Link",
    "50:c7:bf": "TP-Link",
    "00:27:19": "TP-Link",
    "00:14:6c": "Netgear",
    "00:0d:3a": "Microsoft",
    "00:15:5d": "Microsoft",
    "00:17:fa": "Microsoft",
    "00:1d:d8": "Microsoft",
    "00:25:ae": "Microsoft",
    "18:e8:29": "Ubiquiti",
    "24:a4:3c": "Ubiquiti",
    "44:d9:b7": "Ubiquiti",
    "00:16:3e": "Xen",
    "00:1c:58": "Arista",
    "00:1c:73": "Arista",
    "00:23:9a": "Arista",
    "64:0f:28": "Arista",
    "00:1c:2e": "Cisco",
    "00:25:84": "Cisco",
    "00:26:33": "Cisco",
    "f4:cf:e2": "Cisco",
    "00:17:df": "Cisco",
    "00:1a:2b": "Cisco",
    "c8:f7:50": "Cisco",
    "00:24:14": "Cisco",
    "00:0d:56": "Dell",
    "14:fe:b5": "Dell",
    "3c:d9:2b": "HP",
    "00:21:5a": "HP",
    "00:1e:0b": "HP",
    "00:1a:4b": "HP",
    "00:23:cd": "Western Digital",
    "00:00:85": "Canon",
    "00:1e:8f": "Canon",
    "58:35:ea": "Canon",
    "fc:0f:e6": "Canon",
    "04:4b:ed": "Nvidia",
    "00:1f": "ASRock",
    "00:1a:30": "ASRock",
    "00:22:4d": "ASRock",
    "f8:db:88": "ASRock",
    "2c:f0:5d": "ASRock",
    "4c:ed:fb": "ASRock",
}


def _oui_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    prefix = mac.replace(":", "").lower()
    for oui, vendor in MAC_OUI.items():
        if prefix.startswith(oui.replace(":", "").lower()):
            return vendor
    return None


def _get_default_interface() -> str:
    """Detect the default network interface for this host."""
    try:
        proc = subprocess.run(  # nosec B603 B607
            ["ip", "route", "get", "1.1.1.1"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        for line in (proc.stdout or "").splitlines():
            if "dev" in line:
                parts = line.split()
                idx = parts.index("dev") if "dev" in parts else -1
                if idx >= 0 and idx + 1 < len(parts):
                    return parts[idx + 1]
    except Exception:  # nosec B110
        pass
    return os.environ.get("H4K_NET_IFACE", "eth0")


class NeighborFinder:
    def __init__(self, msf: MsfClient, interface: str | None = None):
        self.msf = msf
        self.interface = interface or _get_default_interface()

    def discover(self, target_cidr: str) -> list[Neighbor]:
        """Combine ARP sweep (arp-scan / arp cache / msf arp_sweep) + IPv6 + SNMP."""
        found: dict[str, Neighbor] = {}

        try:
            self.msf.execute(
                "auxiliary",
                "auxiliary/scanner/discovery/arp_sweep",
                {"RHOSTS": target_cidr},
            )
        except Exception as exc:
            logger.warning("arp_sweep failed: %s", exc)

        for entry in self._arp_scan(target_cidr):
            found[entry.ip] = entry

        for entry in self._arp_cache():
            found.setdefault(entry.ip, entry)

        for entry in self._ipv6_neighbor_discovery():
            found[entry.ip] = entry

        for entry in self._snmp_discovery(target_cidr):
            found.setdefault(entry.ip, entry)

        return list(found.values())

    def _arp_scan(self, target: str) -> list[Neighbor]:
        out: list[Neighbor] = []
        proc = subprocess.run(  # nosec B603 B607
            ["arp-scan", f"--interface={self.interface}", target],
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
            proc = subprocess.run(  # nosec B603 B607
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

    def _ipv6_neighbor_discovery(self) -> list[Neighbor]:
        """Discover IPv6 neighbors using ping6 and neighbor cache."""
        out: list[Neighbor] = []
        try:
            subprocess.run(  # nosec B603 B607
                ["ping6", "-c", "2", "-I", self.interface, "ff02::1"],
                capture_output=True,
                timeout=30,
                check=False,
            )
        except FileNotFoundError:
            return out
        except Exception:  # nosec B110
            pass
        try:
            proc = subprocess.run(  # nosec B603 B607
                ["ip", "neighbor", "show"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            for line in (proc.stdout or "").splitlines():
                if "lladdr" in line:
                    m = re.search(r"([0-9a-f:]+)\s+.*?\s+lladdr\s+([0-9a-f:]+)", line)
                    if m:
                        ip, mac = m.groups()
                        out.append(
                            Neighbor(
                                ip=ip,
                                mac=mac,
                                vendor=_oui_vendor(mac) or None,
                            )
                        )
        except Exception as exc:
            logger.debug("IPv6 neighbor discovery failed: %s", exc)
        return out

    def _snmp_discovery(self, target: str) -> list[Neighbor]:
        """Discover hosts via SNMP system description walk."""
        out: list[Neighbor] = []
        try:
            proc = subprocess.run(  # nosec B603 B607
                ["snmpwalk", "-v2c", "-c", "public", target, "1.3.6.1.2.1.1.1.0"],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            for line in (proc.stdout or "").splitlines():
                m = re.search(r"=\s*(.+)$", line)
                if m:
                    desc = m.group(1).strip('" ')
                    if desc:
                        hostname = None
                        mac = None
                        if "hostname" in desc.lower():
                            hn = re.search(r"hostname[:\s]+([^\s,]+)", desc, re.I)
                            if hn:
                                hostname = hn.group(1)
                        out.append(
                            Neighbor(
                                ip=target,
                                mac=mac,
                                vendor=None,
                                hostname=hostname,
                            )
                        )
        except FileNotFoundError:
            logger.debug("snmpwalk not installed; skipping SNMP discovery")
        except Exception as exc:
            logger.debug("SNMP discovery failed for %s: %s", target, exc)
        return out

    @staticmethod
    def neighbors_to_dicts(neighbors: list[Neighbor]) -> list[dict[str, Any]]:
        return [n.model_dump(exclude_none=True) for n in neighbors]
