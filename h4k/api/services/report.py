# Builds the human-facing vulnerability report and prioritized attack
# recommendations from raw Metasploit findings. Stops at "what to attack" —
# it never launches exploitation.
import logging
from datetime import datetime, timezone
from typing import List, Optional

from schemas import Host, Recommendation, Report, Service, Vuln
from services.cve_lookup import CveDb

logger = logging.getLogger("h4k.report")

# CVE/ref keywords -> severity hints used for ranking recommendations.
SEVERITY_HINTS = [
    ("eternalblue", 10, "MS17-010 SMB Remote Code Execution",
     "High-value, high-priority critical Windows exploit."),
    ("smb", 7, "SMB exposure",
     "SMB reachable from network; consider applying SMB patches."),
    ("ms17-010", 10, "EternalBlue (MS17-010)",
     "Critical Windows SMB RCE - patch immediately."),
    ("open", 9, "Unauthenticated access",
     "Service permits unauthenticated or anonymous access."),
    ("anonymous ftp", 6, "Anonymous FTP login",
     "Anonymous FTP enabled - may expose files."),
    ("login", 7, "Weak / default credentials",
     "Service permits brute-forceable authentication."),
    ("version", 3, "Version disclosure",
     "Exposes version banner useful for further exploitation."),
]

def build_report(target: str, mode: str, hosts: List[dict],
                 vulns: List[dict], notes: List[str],
                 cve_db: Optional[CveDb] = None) -> Report:
    host_models = [_host_from_dict(h) for h in hosts]
    vuln_models = [_vuln_from_dict(v) for v in vulns]

    # Match each vuln and each host's services against the local CVE database.
    enriched = (cve_db or CveDb()).enrich(host_models, vuln_models)

    recommendations = _recommendations(
        host_models, vuln_models, enriched
    )

    return Report(
        target=target,
        mode=mode,  # type: ignore[arg-type]
        created_at=datetime.now(timezone.utc).isoformat(),
        hosts=host_models,
        vulns=vuln_models,
        recommendations=recommendations,
        notes=notes + _cve_notes(enriched),
    )


def _host_from_dict(h: dict) -> Host:
    services = [_svc_from_dict(s) for s in h.get("services", [])]
    return Host(
        address=h.get("address", ""),
        hostname=h.get("hostname"),
        os=h.get("os"),
        state=h.get("state"),
        services=services,
    )


def _svc_from_dict(s: dict) -> Service:
    return Service(
        port=s.get("port"),
        proto=s.get("proto", "tcp"),
        service=s.get("service"),
        state=s.get("state"),
        info=s.get("info"),
    )


def _vuln_from_dict(v: dict) -> Vuln:
    refs = v.get("refs") or []
    if isinstance(refs, str):
        refs = [refs]
    return Vuln(
        name=v.get("name", "unknown"),
        refs=refs,
        port=v.get("port"),
        info=v.get("info"),
    )


def _recommendations(hosts: List[Host], vulns: List[Vuln],
                     enriched: dict) -> List[Recommendation]:
    recs: List[Recommendation] = []
    scored: List[tuple[int, str, str, List[str], int, Host, str | None]] = []

    seen_cve = set()
    for host in hosts:
        svc_map = enriched.get("services", {}).get(host.address, {})
        for key, cves in svc_map.items():
            for cve in cves:
                cid = cve.get("id", "")
                if cid in seen_cve:
                    continue
                seen_cve.add(cid)
                port = None
                if ":" in key:
                    try:
                        port = int(key.rsplit(":", 1)[1])
                    except ValueError:
                        port = None
                refs = [cve.get("id", "")]
                scored.append((
                    float(cve.get("cvss", 0.0)) * 10,
                    cve.get("title", cid),
                    cve.get("description", ""),
                    refs,
                    port or 0,
                    host,
                    cve.get("msf_module"),
                ))
    for vuln in vulns:
        host = _host_by_port(hosts, vuln.port) or (hosts[0] if hosts else None)
        if host is None:
            continue
        title, why, score = _describe(vuln)
        scored.append((score, title, why, list(vuln.refs),
                       vuln.port or 0, host, _module_for_vuln(title)))

    scored.sort(key=lambda x: (-x[0], x[1]))
    rank = 1
    taken = set()
    for score, title, why, refs, port, host, module in scored[:15]:
        key = (title, port)
        if key in taken:
            continue
        taken.add(key)
        recs.append(Recommendation(
            rank=rank,
            title=title,
            module=module,
            why=f"{host.address}: {why}",
            difficulty=_difficulty(score),
            refs=list(dict.fromkeys(refs)),
        ))
        rank += 1
    return recs


def _difficulty(score: float) -> str:
    s = int(score)
    if s > 10:  # it was cvss*10
        cvss = s / 10.0
        if cvss >= 9.0:
            return "easy"
        if cvss >= 7.0:
            return "trivial"
        if cvss >= 4.0:
            return "moderate"
        return "hard"
    # vuln hint scale (0..10)
    if s >= 9:
        return "easy"
    if s >= 7:
        return "trivial"
    if s >= 5:
        return "moderate"
    return "hard"


def _cve_notes(enriched: dict) -> List[str]:
    notes = []
    for addr, svc_map in enriched.get("services", {}).items():
        for key, cves in svc_map.items():
            names = ", ".join(
                f"{c.get('id')}({c.get('cvss','?')})"
                for c in cves[:6]
            )
            notes.append(f"[CVE] {addr} {key}: {names}")
    for idx, cves in enriched.get("vulns", {}).items():
        names = ", ".join(c.get("id", "") for c in cves)
        notes.append(f"[CVE] finding#{idx} refs matched: {names}")
    return notes


def _host_by_port(hosts: List[Host], port: int | None) -> Host | None:
    if not port:
        return hosts[0] if hosts else None
    for h in hosts:
        for s in h.services:
            if s.port == port:
                return h
    return None


def _describe(vuln: Vuln) -> tuple[str, str, int]:
    name = (vuln.name or "").lower()
    for keyword, score, title, why in SEVERITY_HINTS:
        if keyword in name or keyword in (vuln.info or "").lower():
            return title, why, score
    return (vuln.name or "Potential vulnerability",
            "Observed service/version warranting manual review", 3)


def _module_for_vuln(title: str) -> str | None:
    t = title.lower()
    if "eternalblue" in t or "ms17-010" in t:
        return "exploit/windows/smb/ms17_010_eternalblue"
    if "anonymous ftp" in t:
        return "auxiliary/scanner/ftp/anonymous"
    if "login" in t or ("credential" in t):
        return "auxiliary/scanner/ssh/ssh_login"
    if "smb" in t:
        return "auxiliary/scanner/smb/smb_enumshares"
    return None
