"""TLS certificate inventory (Backlog #20).

The fingerprint endpoint answers "who is this server". The inventory
answers "which of my servers' certs are about to hurt me": it probes a
list of host:port targets you own and flags expired certs, certs
expiring within 30 days, self-signed certs, and weak protocol/cipher
negotiations. Findings ledger as vuln leads with `engagement_id`
(scope-enforced). Read-only: handshakes only, no exploitation.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from services import tls_fingerprint as _tls

logger = logging.getLogger("h4k.cert_inventory")

EXPIRY_SOON_DAYS = 30


def _parse_asn1_time(text: str) -> datetime | None:
    """Parse OpenSSL ASN.1 time ("Nov  4 12:00:00 2026 GMT")."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            return datetime.strptime(text.strip(), fmt).replace(tzinfo=UTC)
        except (ValueError, AttributeError):
            continue
    return None


def days_until(not_after: str, now: datetime | None = None) -> int | None:
    """Whole days until expiry; negative when expired, None when unparseable."""
    expiry = _parse_asn1_time(not_after)
    if expiry is None:
        return None
    now = now or datetime.now(UTC)
    return int((expiry - now).total_seconds() // 86400)


def cert_leads(
    probe: dict[str, Any], now: datetime | None = None
) -> list[dict[str, str]]:
    """Expiry/self-signed/weak leads for one successful probe."""
    leads: list[dict[str, str]] = list(_tls.flag_probe(probe))
    cert = probe.get("cert") or {}
    if not probe.get("ok"):
        return leads
    remaining = days_until(str(cert.get("not_after") or ""), now)
    if remaining is not None and remaining < 0:
        leads.append({"level": "high", "lead": "certificate expired"})
    elif remaining is not None and remaining <= EXPIRY_SOON_DAYS:
        leads.append(
            {"level": "medium", "lead": f"certificate expires in {remaining} day(s)"}
        )
    return leads


def inventory(
    targets: list[str],
    timeout: float = 10.0,
    watchlist: list[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Probe `host` or `host:port` targets (default 443); inventory + leads."""
    entries: list[dict[str, Any]] = []
    for raw in targets:
        text = str(raw or "").strip()
        if not text:
            continue
        host, _, port_s = text.partition(":")
        try:
            port = int(port_s) if port_s else 443
        except ValueError:
            port = 443
        entry = _tls.probe_host(host, port, timeout=timeout)
        if entry.get("ok"):
            from services.tls_fingerprint import fingerprint

            entry["fingerprint"] = fingerprint(entry)
            entry["leads"] = cert_leads(entry, now) + (
                [{"level": "high", "lead": "fingerprint on operator watchlist"}]
                if entry["fingerprint"] in set(watchlist or [])
                else []
            )
        entries.append(entry)
    ok = [e for e in entries if e.get("ok")]
    return {
        "targets": [e["host"] for e in entries],
        "entries": entries,
        "count": len(ok),
        "lead_count": sum(len(e.get("leads", [])) for e in ok),
        "fingerprints": sorted({e["fingerprint"] for e in ok if e.get("fingerprint")}),
    }


def sandbox_inventory(targets: list[str]) -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    from services.tls_fingerprint import sandbox_scan

    hosts = [str(t or "").strip().split(":")[0] or "sandbox" for t in targets] or [
        "sandbox"
    ]
    entries = []
    for host in hosts:
        result = sandbox_scan(host)
        probe = dict(result["probes"][0])
        probe["leads"] = []
        entries.append(probe)
    return {
        "targets": hosts,
        "entries": entries,
        "count": len(entries),
        "lead_count": 0,
        "fingerprints": sorted({e["fingerprint"] for e in entries}),
        "sandbox": True,
    }
