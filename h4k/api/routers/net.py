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


# ---- passive network sniffing (opt-in, lab-scoped) -------------------------
@router.post("/sniff/deep")
def net_sniff_deep(body: dict[str, Any]) -> dict[str, Any]:
    """Capture live traffic on an interface, dissect it (hosts, flows, cleartext
    credentials, TLS certificates, DNS, anomalies) and, when an engagement is
    active, fold the findings into the engagement graph."""
    from services.passive_sniff import PassiveSniffer

    interface = (body or {}).get("interface") or "eth0"
    duration = int((body or {}).get("duration", 30))
    bpf_filter = (body or {}).get("filter")
    eng_id, store = None, None
    try:
        from routers.scan import _active_scope as _as

        eng_id, store = _as()
    except Exception:
        eng_id, store = None, None
    result = PassiveSniffer().capture_live(
        interface, duration, bpf_filter, eng_id, store
    )
    return result


@router.post("/sniff/pcap")
def net_sniff_pcap(body: dict[str, Any]) -> dict[str, Any]:
    """Analyse a previously captured pcap file (no live capture)."""
    from services.passive_sniff import PassiveSniffer

    pcap_file = str((body or {}).get("pcap_file") or "").strip()
    if not pcap_file:
        raise HTTPException(status_code=400, detail="pcap_file required")
    eng_id, store = None, None
    try:
        from routers.scan import _active_scope as _as

        eng_id, store = _as()
    except Exception:
        eng_id, store = None, None
    return PassiveSniffer().analyze_pcap(pcap_file, eng_id, store)


@router.post("/ipv6/discover")
def net_ipv6_discover(body: dict[str, Any]) -> dict[str, Any]:
    """IPv6 discovery: NDP neighbour table + optional explicit-CIDR sweep.

    `engagement_id` records in-scope hosts as assets; out-of-scope
    addresses are reported and never stored. Sandbox returns canned hosts.
    """
    from services import sandbox as sandbox_mode
    from services.ipv6_discovery import discover, sandbox_discover

    interface = str((body or {}).get("interface") or "").strip() or None
    cidr = str((body or {}).get("cidr") or "").strip() or None
    engagement_id = str((body or {}).get("engagement_id") or "").strip() or None
    if sandbox_mode.enabled():
        result = sandbox_discover()
    else:
        result = discover(interface=interface, cidr=cidr)
    recorded = 0
    skipped: list[str] = []
    if engagement_id:
        from routers.engagement import get_store
        from services.engagement import ScopeError

        store = get_store()
        if not store.get_engagement(engagement_id):
            raise HTTPException(status_code=404, detail="engagement not found")
        for n in result.get("neighbors", []):
            try:
                recorded += store.upsert_asset(engagement_id, n["ip"])
            except (ScopeError, ValueError):
                skipped.append(n["ip"])
    return {**result, "recorded": recorded, "skipped_out_of_scope": skipped}


@router.post("/tunnel")
def net_tunnel_start(body: dict[str, Any]) -> dict[str, Any]:
    """One-click pivot tunnel: SSH dynamic forward or chisel server, loopback-only.

    Sandbox returns a canned tunnel without spawning anything.
    """
    from services import sandbox as sandbox_mode
    from services.pivot_tunnel import list_tunnels, sandbox_tunnels, start_tunnel

    if sandbox_mode.enabled():
        return sandbox_tunnels()
    kind = str((body or {}).get("kind") or "ssh").strip().lower()
    try:
        port = int((body or {}).get("port") or 0)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="port must be an integer") from None
    try:
        out = start_tunnel(
            kind,
            port=port,
            target=str((body or {}).get("target") or ""),
            ssh_host=str((body or {}).get("ssh_host") or ""),
            ssh_user=str((body or {}).get("ssh_user") or ""),
            ssh_port=int((body or {}).get("ssh_port") or 22),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not out.get("success"):
        raise HTTPException(status_code=502, detail=out.get("error", "tunnel failed"))
    out["tunnels"] = list_tunnels()["tunnels"]
    return out


@router.get("/tunnels")
def net_tunnels() -> dict[str, Any]:
    """Tracked tunnels with liveness."""
    from services import sandbox as sandbox_mode
    from services.pivot_tunnel import list_tunnels, sandbox_tunnels

    if sandbox_mode.enabled():
        return sandbox_tunnels()
    return list_tunnels()


@router.delete("/tunnels/{tunnel_id}")
def net_tunnel_stop(tunnel_id: str) -> dict[str, Any]:
    """Stop a tracked tunnel and forget it."""
    from services.pivot_tunnel import stop_tunnel

    out = stop_tunnel(tunnel_id)
    if not out.get("stopped"):
        raise HTTPException(status_code=404, detail=out.get("error", "unknown tunnel"))
    return out


@router.post("/tunnel/scan")
def net_tunnel_scan(body: dict[str, Any]) -> dict[str, Any]:
    """Proxied rescan: TCP connect + banner grab through a SOCKS proxy.

    Give `tunnel_id` (uses its listen port) or an explicit `proxy`
    `host:port`. Sandbox returns a canned scan.
    """
    from services import sandbox as sandbox_mode
    from services.pivot_tunnel import list_tunnels, proxied_scan, sandbox_scan

    target = str((body or {}).get("target") or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target required")
    if sandbox_mode.enabled():
        return sandbox_scan(target)
    ports = (body or {}).get("ports") or [22, 80, 443, 445, 3389, 8080, 8443]
    try:
        ports = [int(p) for p in ports][:64]
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="ports must be integers") from None
    proxy = str((body or {}).get("proxy") or "").strip()
    tunnel_id = str((body or {}).get("tunnel_id") or "").strip()
    if tunnel_id and not proxy:
        found = [
            t
            for t in list_tunnels()["tunnels"]
            if t["id"] == tunnel_id and t.get("alive")
        ]
        if not found:
            raise HTTPException(status_code=404, detail="tunnel not found or not alive")
        proxy = str(found[0].get("listen") or "")
    if not proxy or ":" not in proxy:
        raise HTTPException(
            status_code=400, detail="proxy host:port (or a live tunnel_id) required"
        )
    host, _, port_s = proxy.rpartition(":")
    try:
        return proxied_scan(host or "127.0.0.1", int(port_s), target, ports)
    except ValueError:
        raise HTTPException(status_code=400, detail="bad proxy port") from None
    except OSError as exc:
        raise HTTPException(
            status_code=502, detail=f"proxy unreachable: {exc}"
        ) from exc
