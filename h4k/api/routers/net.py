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


# ---- local TLS interception lab (opt-in, loopback-only) ----
# Build a private CA, sign a localhost cert, install the CA into the container's
# trust store, and expose an owned plain-HTTP lab target over HTTPS on loopback
# so fuzzer/SAST can target an https:// web app you own with a trusted cert.
@router.get("/tls/status")
def tls_status() -> dict[str, Any]:
    """Report TLS-lab readiness (openssl present? CA installed?)."""
    from services.tls_lab import status

    return status()


@router.post("/tls/setup")
def tls_setup() -> dict[str, Any]:
    """Generate the lab CA + localhost server cert (idempotent)."""
    from services.tls_lab import setup_ca

    return setup_ca()


@router.post("/tls/trust")
def tls_trust() -> dict[str, Any]:
    """Install the lab CA into the container's system trust store."""
    from services.tls_lab import install_ca_to_trust

    return install_ca_to_trust()


@router.post("/tls/proxy")
def tls_proxy(body: dict[str, Any]) -> dict[str, Any]:
    """HTTPS sidecar in front of a plain-HTTP loopback lab target.
    body={backend_host?, backend_port?, listen_port?}."""
    from services.tls_lab import start_https_proxy

    return start_https_proxy(
        listen_port=int((body or {}).get("listen_port", 8443)),
        backend_host=str((body or {}).get("backend_host", "127.0.0.1")),
        backend_port=int((body or {}).get("backend_port", 8080)),
    )
