# Builds the human-facing vulnerability report and prioritized attack
# recommendations from raw Metasploit findings. Stops at "what to attack" —
# it never launches exploitation.
import logging
from datetime import datetime, timezone
from typing import List

from schemas import Host, Recommendation, Report, Service, Vuln

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

DIFFICULTY = {
    10: "trivial",
    8: "easy",
    6: "moderate",
    4: "hard",
    2: "hard",
}


def score_vuln(vuln: Vuln, svc: str | None = None) -> int:
    name = (vuln.name or "").lower()
    info = (vuln.info or "").lower()
    svc = (svc or "").lower()
    joined = f"{name} {info}"
    best = 0
    for keyword, score, _title, _why in SEVERITY_HINTS:
        if keyword in joined or keyword in svc:
            best = max(best, score)
    return best


def build_report(target: str, mode: str, hosts: List[dict],
                 vulns: List[dict], notes: List[str]) -> Report:
    host_models = [_host_from_dict(h) for h in hosts]
    vuln_models = [_vuln_from_dict(v) for v in vulns]

    # Match each vuln to a service on a host for contextual recommendations.
    recommendations = _recommendations(host_models, vuln_models)

    return Report(
        target=target,
        mode=mode,  # type: ignore[arg-type]
        created_at=datetime.now(timezone.utc).isoformat(),
        hosts=host_models,
        vulns=vuln_models,
        recommendations=recommendations,
        notes=notes,
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


def _recommendations(hosts: List[Host], vulns: List[Vuln]) -> List[Recommendation]:
    recs: List[Recommendation] = []
    scored: List[tuple[int, str, str, List[str], int, Host, Vuln]] = []

    for vuln in vulns:
        host = _host_by_port(hosts, vuln.port) or (hosts[0] if hosts else None)
        if host is None:
            continue
        port_desc = f" (port {vuln.port})" if vuln.port else ""
        title, why, score = _describe(vuln)
        scored.append((score, title, why, vuln.refs, vuln.port or 0, host, vuln))

    scored.sort(key=lambda x: (-x[0], x[1]))
    rank = 1
    taken = set()
    for score, title, why, refs, port, host, vuln in scored[:10]:
        key = (title, port)
        if key in taken:
            continue
        taken.add(key)
        recs.append(Recommendation(
            rank=rank,
            title=title,
            module=_module_for_vuln(title),
            why=f"{host.address}: {why}",
            difficulty=DIFFICULTY.get(score, "hard"),
            refs=refs,
        ))
        rank += 1
    return recs


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
