# Opt-in network-layer lab endpoints: local sniffing, ARP, bettercap MITM, and
# WiFi capture/cracking. All are for authorized lab use on networks you own.
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from services import sniffer

logger = logging.getLogger("h4k.routers.net")

router = APIRouter(prefix="/api/net")

_jobs: dict[str, dict[str, Any]] = {}


@router.get("/interfaces")
def net_interfaces() -> dict[str, Any]:
    """List available network interfaces (for tcpdump/airmon)."""
    return {"interfaces": sniffer.detect_interfaces()}


@router.post("/sniff")
def net_sniff(body: dict[str, Any]) -> dict[str, Any]:
    """Capture a few packets on an interface (tcpdump). body={interface,count?}."""
    interface = (body or {}).get("interface") or "eth0"
    return sniffer.sniff_packets(
        interface,
        count=int((body or {}).get("count", 20)),
        timeout=int((body or {}).get("timeout", 15)),
    )


@router.post("/arp")
def net_arp(body: dict[str, Any]) -> dict[str, Any]:
    """Show recent ARP activity on an interface."""
    interface = (body or {}).get("interface") or "eth0"
    return sniffer.arp_who(interface)


@router.post("/mitm")
def net_mitm(body: dict[str, Any]) -> dict[str, Any]:
    """Run a short bettercap ARP-spoof on a lab target (opt-in, brief)."""
    interface = (body or {}).get("interface") or "eth0"
    target = (body or {}).get("target") or ""
    seconds = int((body or {}).get("seconds", 20))
    if not target:
        raise HTTPException(status_code=400, detail="target IP required")
    result = sniffer.mitm_arp_poison(interface, target, seconds)
    return result


@router.post("/wifi/scan")
def net_wifi_scan(body: dict[str, Any]) -> dict[str, Any]:
    """Scan nearby APs with airmon/airodump on a monitor interface."""
    interface = (body or {}).get("interface") or ""
    if not interface:
        raise HTTPException(
            status_code=400, detail="interface (monitor-capable) required"
        )
    return sniffer.wifi_scan(interface)


@router.post("/wifi/capture")
def net_wifi_capture(body: dict[str, Any]) -> dict[str, Any]:
    """Capture raw frames for offline cracking (airodump-ng)."""
    interface = (body or {}).get("interface") or ""
    if not interface:
        raise HTTPException(status_code=400, detail="interface required")
    return sniffer.wifi_capture(
        interface,
        seconds=int((body or {}).get("seconds", 20)),
        channel=str((body or {}).get("channel", "6")),
    )
