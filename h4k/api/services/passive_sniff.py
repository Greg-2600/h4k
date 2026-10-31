"""Passive network sniffing: capture traffic, find vulnerabilities, feed the
engagement graph.

This is the bridge between the low-level capture tools (tcpdump/tshark) and
h4k's analysis layer. A single run:

  1. captures traffic on an interface (or reads a pcap)
  2. dissects it: hosts, flows, cleartext credentials, TLS certificates,
     DNS queries, anomalies (SYN scans, tunneling, unusual ports)
  3. folds the result into the active engagement: sniffed hosts become
     assets, sniffed credentials become verified credentials, and every
     anomaly becomes a finding tagged with its ATT&CK technique

All of it is opt-in and lab-scoped; the operator picks the interface and the
duration, and the capture stops when the duration elapses.

It builds on ``services.tshark`` and ``services.sniffer`` rather than
reimplementing them, so the same pcap parsing and credential extraction
code is used everywhere.
"""

from __future__ import annotations

import contextlib
import logging
import os
import tempfile
from collections.abc import Callable
from typing import Any

logger = logging.getLogger("h4k.passive_sniff")

# Cleartext credentials are a finding, not just a log line.
CLEARTEXT_CRED_CLASSES: dict[str, str] = {
    "http_basic": "CWE-522",  # Insufficiently Protected Credentials
    "ftp": "CWE-522",
    "telnet": "CWE-522",
    "smtp": "CWE-522",
    "snmp": "CWE-798",  # Use of Hard-coded Credentials (community string)
}

# Protocol -> ATT&CK technique id (coarse, honest labels).
TECHNIQUE_FOR: dict[str, str] = {
    "http_basic": "T1078",  # Valid Accounts
    "ftp": "T1078",
    "telnet": "T1021",
    "smtp": "T1078",
    "snmp": "T1078",
    "tls_weak": "T1557",  # Adversary-in-the-Middle
    "arp_spoof": "T1557",
    "dns_tunnel": "T1071",  # Application Layer Protocol
    "syn_scan": "T1046",  # Network Service Discovery
}


class PassiveSniffer:
    """Capture + analyse + fold into the engagement graph."""

    def __init__(self, progress: Callable[[str, float], None] | None = None):
        self.progress = progress or (lambda msg, pct: None)

    def _run_tshark(
        self, pcap_file: str, display_filter: str, fields: list[str]
    ) -> str:
        from services.tshark import TsharkService

        svc = TsharkService(self.progress)
        return svc._field_query(pcap_file, display_filter, fields)

    def analyze_pcap(
        self,
        pcap_file: str,
        engagement_id: str | None = None,
        store: Any = None,
    ) -> dict[str, Any]:
        """Analyse a pcap and, when an engagement is active, fold the
        findings into the engagement store."""
        from services.tshark import TsharkService

        self.progress("analysing pcap", 10)
        svc = TsharkService(self.progress)
        stats = svc.pcap_stats(pcap_file)
        flows = svc.extract_flows(pcap_file)
        creds = svc.extract_credentials(pcap_file)
        anomalies = svc.detect_anomalies(pcap_file)

        self.progress("analysing TLS certificates", 55)
        tls = self._tls_analysis(pcap_file)

        self.progress("detecting ARP spoofing", 70)
        arp = self._arp_analysis(pcap_file)

        self.progress("analysing DNS", 80)
        dns = self._dns_analysis(pcap_file)

        self.progress("extracting transferred files", 90)
        extracted = svc.extract_files(
            pcap_file, tempfile.mkdtemp(prefix="passive_sniff_")
        )  # nosec B108

        # Parse the cleartext credentials into structured records.
        parsed_creds = self._parse_credentials(creds)
        parsed_hosts = self._parse_hosts(flows)
        parsed_findings = self._build_findings(parsed_creds, anomalies, tls, arp, dns)

        # Fold into the engagement store when one is active.
        ingestion: dict[str, Any] = {"hosts": 0, "credentials": 0, "findings": 0}
        if engagement_id and store is not None:
            ingestion = self._ingest(
                store, engagement_id, parsed_hosts, parsed_creds, parsed_findings
            )

        self.progress("done", 100)
        return {
            "pcap_file": pcap_file,
            "stats": stats.get("stats", ""),
            "flows": flows,
            "credentials": creds,
            "parsed_credentials": parsed_creds,
            "parsed_hosts": parsed_hosts,
            "findings": parsed_findings,
            "tls": tls,
            "arp": arp,
            "dns": dns,
            "anomalies": anomalies,
            "extracted_files": extracted,
            "ingestion": ingestion,
        }

    def capture_live(
        self,
        interface: str,
        duration: int = 60,
        bpf_filter: str | None = None,
        engagement_id: str | None = None,
        store: Any = None,
    ) -> dict[str, Any]:
        """Capture live traffic to a temp pcap, then analyse it."""
        from services.tshark import TsharkService

        self.progress("capturing live traffic", 5)
        svc = TsharkService(self.progress)
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            pcap = fh.name
        try:
            capture = svc.capture_live(interface, duration, bpf_filter, pcap)
            if not capture.get("success") and capture.get("rc") not in (0, 1):
                return {"error": capture.get("stderr", "capture failed"), "pcap": pcap}
            result = self.analyze_pcap(pcap, engagement_id, store)
            result["capture"] = capture
            return result
        finally:
            with contextlib.suppress(OSError):
                os.unlink(pcap)

    # ---- analysis helpers --------------------------------------------------

    def _parse_hosts(self, flows: dict[str, Any]) -> list[str]:
        """Pull unique IP addresses from the conversation output."""
        hosts: set[str] = set()
        for block in (flows.get("tcp_endpoints", ""), flows.get("udp_endpoints", "")):
            for line in str(block).splitlines():
                for token in line.split():
                    if _looks_like_ip(token):
                        hosts.add(token.strip(".,:"))
        return sorted(hosts)

    def _parse_credentials(self, creds: dict[str, Any]) -> list[dict[str, Any]]:
        """Turn tshark field output into structured credential records."""
        records: list[dict[str, Any]] = []
        # http basic: frame.time, ip.src, http.authbasic
        for line in str(creds.get("http_basic") or "").splitlines():
            parts = [p.strip() for p in line.split("\t")]
            if len(parts) >= 3 and parts[2]:
                decoded = _decode_basic(parts[2])
                if decoded:
                    user, password = decoded
                    records.append(
                        {
                            "protocol": "http_basic",
                            "host": parts[1] if len(parts) > 1 else None,
                            "user": user,
                            "password": password,
                            "cwe": CLEARTEXT_CRED_CLASSES["http_basic"],
                            "technique": TECHNIQUE_FOR["http_basic"],
                        }
                    )
        # ftp
        for line in str(creds.get("ftp") or "").splitlines():
            parts = [p.strip() for p in line.split("\t")]
            if len(parts) >= 4 and parts[2].upper() == "USER":
                # pair with the following PASS line (best-effort)
                records.append(
                    {
                        "protocol": "ftp",
                        "host": parts[1] if len(parts) > 1 else None,
                        "user": parts[3],
                        "password": None,  # nosec B105 - sentinel for "no password captured"
                        "cwe": CLEARTEXT_CRED_CLASSES["ftp"],
                        "technique": TECHNIQUE_FOR["ftp"],
                    }
                )
        # telnet
        for line in str(creds.get("telnet") or "").splitlines():
            parts = [p.strip() for p in line.split("\t")]
            if len(parts) >= 3 and parts[2]:
                records.append(
                    {
                        "protocol": "telnet",
                        "host": parts[1] if len(parts) > 1 else None,
                        "user": None,
                        "password": parts[2],
                        "cwe": CLEARTEXT_CRED_CLASSES["telnet"],
                        "technique": TECHNIQUE_FOR["telnet"],
                    }
                )
        # snmp community strings
        for line in str(creds.get("snmp") or "").splitlines():
            parts = [p.strip() for p in line.split("\t")]
            if len(parts) >= 3 and parts[2]:
                records.append(
                    {
                        "protocol": "snmp",
                        "host": parts[1] if len(parts) > 1 else None,
                        "user": "community",
                        "password": parts[2],
                        "cwe": CLEARTEXT_CRED_CLASSES["snmp"],
                        "technique": TECHNIQUE_FOR["snmp"],
                    }
                )
        return records

    def _decode_basic(self, value: str) -> tuple[str, str] | None:
        import base64

        value = value.strip()
        if value.lower().startswith("basic "):
            value = value[6:]
        try:
            raw = base64.b64decode(value, validate=True).decode(
                "utf-8", errors="replace"
            )
        except Exception:
            return None
        if ":" not in raw:
            return None
        user, _, password = raw.partition(":")
        return user, password

    def _tls_analysis(self, pcap_file: str) -> dict[str, Any]:
        """Analyse TLS handshakes captured in the pcap."""
        out: dict[str, Any] = {
            "servers": [],
            "weak_protocols": [],
            "expired_certificates": [],
        }
        try:
            raw = self._run_tshark(
                pcap_file,
                "tls.handshake.type == 2",
                ["ip.dst", "tls.handshake.ciphersuite"],
            )
            for line in raw.splitlines():
                parts = [p.strip() for p in line.split("\t")]
                if len(parts) >= 2 and parts[0]:
                    out["servers"].append({"host": parts[0], "cipher": parts[1]})
                    cipher = (parts[1] or "").lower()
                    if any(
                        weak in cipher
                        for weak in ("rc4", "des", "md5", "null", "export", "anon")
                    ):
                        out["weak_protocols"].append(parts[0])
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("tls analysis failed: %s", exc)
        return out

    def _arp_analysis(self, pcap_file: str) -> dict[str, Any]:
        """Look for ARP spoofing: the same IP claiming multiple MACs."""
        seen: dict[str, set[str]] = {}
        try:
            raw = self._run_tshark(
                pcap_file, "arp", ["arp.src.proto_ipv4", "arp.src.hw_mac"]
            )
            for line in raw.splitlines():
                parts = [p.strip() for p in line.split("\t")]
                if len(parts) >= 2 and parts[0] and parts[1]:
                    seen.setdefault(parts[0], set()).add(parts[1])
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("arp analysis failed: %s", exc)
        spoofed = {ip: macs for ip, macs in seen.items() if len(macs) > 1}
        return {"hosts": {k: sorted(v) for k, v in seen.items()}, "spoofed": spoofed}

    def _dns_analysis(self, pcap_file: str) -> dict[str, Any]:
        """DNS queries: tunneling (long names) and unusual record types."""
        out: dict[str, Any] = {"queries": [], "long_names": [], "suspicious": []}
        try:
            raw = self._run_tshark(
                pcap_file,
                "dns.qry.name",
                ["ip.src", "dns.qry.name", "dns.qry.type"],
            )
            for line in raw.splitlines():
                parts = [p.strip() for p in line.split("\t")]
                if len(parts) >= 2 and parts[1]:
                    out["queries"].append(
                        {
                            "src": parts[0],
                            "name": parts[1],
                            "type": parts[2] if len(parts) > 2 else "",
                        }
                    )
                    if len(parts[1]) > 50:
                        out["long_names"].append(parts[1])
                    name = parts[1].lower()
                    if any(
                        s in name for s in ("pastebin", "discord", "ngrok", "pastebin")
                    ):
                        out["suspicious"].append(parts[1])
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("dns analysis failed: %s", exc)
        return out

    def _build_findings(
        self,
        creds: list[dict[str, Any]],
        anomalies: dict[str, Any],
        tls: dict[str, Any],
        arp: dict[str, Any],
        dns: dict[str, Any],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        # cleartext credentials
        for cred in creds:
            if not cred.get("user") and not cred.get("password"):
                continue
            findings.append(
                {
                    "kind": "cleartext_credential",
                    "severity": "high",
                    "host": cred.get("host"),
                    "protocol": cred.get("protocol"),
                    "user": cred.get("user"),
                    "password": cred.get("password"),
                    "detail": (
                        f"cleartext {cred.get('protocol')} credential "
                        f"{cred.get('user') or '?'}:{cred.get('password') or '?'}"
                    ),
                    "technique": cred.get("technique"),
                    "cwe": cred.get("cwe")
                    or CLEARTEXT_CRED_CLASSES.get(
                        str(cred.get("protocol") or ""), "CWE-522"
                    ),
                }
            )
        # anomalies
        for name in ("syn_scans", "dns_tunneling", "unusual_ports"):
            raw = anomalies.get(name) or ""
            if str(raw).strip():
                findings.append(
                    {
                        "kind": name,
                        "severity": "medium",
                        "detail": f"traffic anomaly: {name.replace('_', ' ')}",
                        "evidence": str(raw)[:400],
                        "technique": TECHNIQUE_FOR.get(name.replace("_", "_"), "T1046"),
                    }
                )
        # weak TLS
        for host in tls.get("weak_protocols") or []:
            findings.append(
                {
                    "kind": "weak_tls",
                    "severity": "medium",
                    "host": host,
                    "detail": f"weak TLS cipher suite observed on {host}",
                    "technique": TECHNIQUE_FOR["tls_weak"],
                    "cwe": "CWE-326",
                }
            )
        # expired / soon-to-expire certificates
        for host in tls.get("expired_certificates") or []:
            findings.append(
                {
                    "kind": "expired_certificate",
                    "severity": "medium",
                    "host": host,
                    "detail": f"expired TLS certificate observed on {host}",
                    "technique": TECHNIQUE_FOR["tls_weak"],
                    "cwe": "CWE-295",
                }
            )
        # ARP spoofing
        for ip, macs in (arp.get("spoofed") or {}).items():
            findings.append(
                {
                    "kind": "arp_spoof",
                    "severity": "high",
                    "host": ip,
                    "detail": f"ARP spoofing: {ip} claimed by {len(macs)} MACs",
                    "technique": TECHNIQUE_FOR["arp_spoof"],
                    "cwe": "CWE-290",
                    "macs": macs,
                }
            )
        # DNS tunneling
        for name in dns.get("long_names") or []:
            findings.append(
                {
                    "kind": "dns_tunnel",
                    "severity": "medium",
                    "detail": f"suspiciously long DNS name (tunneling candidate): {name[:120]}",
                    "technique": TECHNIQUE_FOR["dns_tunnel"],
                    "cwe": "CWE-20",
                }
            )
        return findings

    def _ingest(
        self,
        store: Any,
        engagement_id: str,
        hosts: list[str],
        creds: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Fold the capture result into the engagement store."""
        added: dict[str, int] = {
            "hosts": 0,
            "credentials": 0,
            "findings": 0,
        }
        skipped: list[str] = []
        for host in hosts:
            if not store.in_scope(engagement_id, host):
                skipped.append(host)
                continue
            try:
                store.upsert_asset(engagement_id, host)
                added["hosts"] += 1
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("upsert_asset failed for %s: %s", host, exc)
        for cred in creds:
            chost: str = str(cred.get("host") or "")
            if not chost or not store.in_scope(engagement_id, chost):
                if chost:
                    skipped.append(chost)
                continue
            if cred.get("user") or cred.get("password"):
                store.record_credential(
                    engagement_id,
                    cred.get("user") or "unknown",
                    cred.get("password") or "",
                    cred.get("protocol") or "sniffed",
                    origin_host=chost,
                    origin_port=0,
                    verified=True,
                )
                added["credentials"] += 1
        for finding in findings:
            fhost: str = str(finding.get("host") or "")
            if fhost and not store.in_scope(engagement_id, fhost):
                skipped.append(fhost)
                continue
            store.record_vuln(
                engagement_id,
                fhost or "network",
                {
                    "name": finding.get("detail")
                    or finding.get("kind", "sniffed finding"),
                    "severity": finding.get("severity"),
                    "cwe": finding.get("cwe"),
                    "module": None,
                    "reference": finding.get("technique"),
                },
            )
            added["findings"] += 1
        return {"added": added, "skipped_out_of_scope": sorted(set(skipped))}


def _looks_like_ip(token: str) -> bool:
    import re

    if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", token):
        return False
    return all(0 <= int(part) <= 255 for part in token.split("."))


def _decode_basic(value: str) -> tuple[str, str] | None:
    import base64

    value = value.strip()
    if value.lower().startswith("basic "):
        value = value[6:]
    try:
        raw = base64.b64decode(value, validate=True).decode("utf-8", errors="replace")
    except Exception:
        return None
    if ":" not in raw:
        return None
    user, _, password = raw.partition(":")
    return user, password
