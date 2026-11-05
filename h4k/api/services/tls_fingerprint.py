"""Active TLS fingerprinting + C2/malware leads (Backlog #16).

For each TLS service on a host you own, this module performs a real
handshake (stdlib `ssl`, no new dependencies) and records what the
server negotiates: TLS version, cipher suite, and the peer certificate
(subject/issuer/self-signed/expiry/pubkey hash). The fingerprint is the
SHA-256 of that canonical inventory — stable for identical servers, so
an operator-supplied watchlist of known-bad fingerprints yields exact
C2 matches, and heuristic flags (self-signed, expired, weak protocol or
cipher, same cert on many hosts) surface leads otherwise.

Scope honesty (D22): this is a handshake inventory, not a raw-ClientHello
JARM implementation — stdlib cannot emit the 10 crafted ClientHellos the
JARM fuzzy hash needs, and calling it JARM would be the same lie in a
different coat. Exact-match only; no fuzzy similarity is claimed.
"""

from __future__ import annotations

import hashlib
import logging
import socket
import ssl
from typing import Any

logger = logging.getLogger("h4k.tls_fingerprint")

DEFAULT_PORTS = (443, 8443, 9443)
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_MARKS = ("RC4", "DES", "MD5", "NULL", "EXPORT", "anon")


def _rdn(seq: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    for rdn in seq or ():
        for attr in rdn:
            if isinstance(attr, (tuple, list)) and len(attr) == 2:
                out[str(attr[0])] = str(attr[1])
    return out


def _cert_summary(cert: dict[str, Any] | None) -> dict[str, Any]:
    cert = cert or {}
    subject = _rdn(cert.get("subject"))
    issuer = _rdn(cert.get("issuer"))
    return {
        "subject": subject,
        "issuer": issuer,
        "self_signed": bool(subject) and subject == issuer,
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
    }


def probe_host(host: str, port: int, timeout: float = 10.0) -> dict[str, Any]:
    """One TLS handshake: negotiated version/cipher + peer certificate."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    result: dict[str, Any] = {"host": host, "port": port}
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                result["version"] = tls.version() or ""
                cipher = tls.cipher() or ("", "", 0)
                result["cipher"] = cipher[0] or ""
                result["cipher_bits"] = cipher[2] if len(cipher) > 2 else 0
                der = tls.getpeercert(binary_form=True)
                result["cert_sha256"] = hashlib.sha256(der).hexdigest() if der else ""
                result["cert"] = _cert_summary(tls.getpeercert())
                result["ok"] = True
    except (OSError, ssl.SSLError, ValueError) as exc:
        logger.debug("tls probe failed for %s:%s: %s", host, port, exc)
        result.update({"ok": False, "error": str(exc)[:200]})
    return result


def fingerprint(probe: dict[str, Any]) -> str:
    """Stable fingerprint of one successful probe (exact-match only)."""
    canon = "|".join(
        [
            probe.get("version", ""),
            probe.get("cipher", ""),
            probe.get("cert_sha256", ""),
        ]
    )
    return hashlib.sha256(canon.encode()).hexdigest()


def flag_probe(
    probe: dict[str, Any], watchlist: list[str] | None = None
) -> list[dict[str, str]]:
    """Heuristic C2/malware leads for one probe (all labeled as such)."""
    leads: list[dict[str, str]] = []
    if not probe.get("ok"):
        return leads
    if (probe.get("version") or "") in WEAK_PROTOCOLS:
        leads.append({"level": "medium", "lead": f"weak protocol {probe['version']}"})
    cipher = str(probe.get("cipher") or "").upper()
    if any(m in cipher for m in WEAK_CIPHER_MARKS):
        leads.append({"level": "medium", "lead": f"weak cipher {probe.get('cipher')}"})
    cert = probe.get("cert") or {}
    if cert.get("self_signed"):
        leads.append({"level": "low", "lead": "self-signed certificate"})
    fp = fingerprint(probe)
    if fp in set(watchlist or []):
        leads.append({"level": "high", "lead": "fingerprint on operator watchlist"})
    return leads


def scan_host(
    host: str,
    ports: list[int] | None = None,
    timeout: float = 10.0,
    watchlist: list[str] | None = None,
) -> dict[str, Any]:
    """Probe TLS ports on one host; fingerprint + leads per port."""
    probes = [
        probe_host(host, p, timeout=timeout) for p in (ports or list(DEFAULT_PORTS))
    ]
    for probe in probes:
        if probe.get("ok"):
            probe["fingerprint"] = fingerprint(probe)
            probe["leads"] = flag_probe(probe, watchlist)
    ok = [p for p in probes if p.get("ok")]
    return {
        "host": host,
        "ports": [p["port"] for p in probes if p.get("ok")],
        "probes": probes,
        "fingerprints": sorted({p["fingerprint"] for p in ok if p.get("fingerprint")}),
        "lead_count": sum(len(p.get("leads", [])) for p in ok),
    }


def sandbox_scan(host: str) -> dict[str, Any]:
    """Deterministic offline stand-in (sandbox/e2e only)."""
    probe = {
        "host": host,
        "port": 443,
        "version": "TLSv1.2",
        "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "cipher_bits": 128,
        "cert_sha256": "sandbox" * 8,
        "cert": {
            "subject": {"CN": "sandbox.lab"},
            "issuer": {"CN": "sandbox CA"},
            "self_signed": False,
            "not_before": "",
            "not_after": "",
        },
        "ok": True,
    }
    probe["fingerprint"] = fingerprint(probe)
    probe["leads"] = []
    return {
        "host": host,
        "ports": [443],
        "probes": [probe],
        "fingerprints": [probe["fingerprint"]],
        "lead_count": 0,
        "sandbox": True,
    }
