# Generates a consolidated, exportable report that merges findings from every
# h4k source: host scan, SAST, SCA, fuzzing, and triage. One click -> one .md
# (or .json) deliverable, which is what you hand back as the assessment.
import json
from datetime import UTC, datetime
from typing import Any


def _ts() -> str:
    return datetime.now(UTC).isoformat()


def _dedupe(items: list[str]) -> list[str]:
    seen: list[str] = []
    for i in items:
        if i and i not in seen:
            seen.append(i)
    return seen


def build_merged_report(
    scan: list[dict] | None = None,
    sast: list[dict] | None = None,
    sca: dict | None = None,
    fuzz: list[dict] | None = None,
    triage: list[dict] | None = None,
) -> dict[str, Any]:
    """Merge all sections into one structured report dict."""
    scan = scan or []
    sast = sast or []
    fuzz = fuzz or []
    triage = triage or []
    sca = sca or {}

    cves = _dedupe(list(sca.get("cves", [])))
    if sca.get("vulnerabilities"):
        for v in sca["vulnerabilities"]:
            if v.get("cve"):
                cves.append(str(v["cve"]))
        cves = _dedupe(cves)

    return {
        "generated": _ts(),
        "summary": {
            "hosts_scanned": len(scan),
            "sast_findings": len(sast),
            "sca_cves": len(cves),
            "fuzz_candidates": len(fuzz),
            "triage_reports": len(triage),
        },
        "scan": scan,
        "sast": sast,
        "sca": {
            "cves": cves,
            "packages": sca.get("packages", []),
            "vulnerabilities": sca.get("vulnerabilities", []),
        },
        "fuzz": fuzz,
        "triage": triage,
    }


def render_markdown(rep: dict[str, Any]) -> str:
    L: list[str] = []
    s = rep.get("summary", {})
    L.append("# h4k — consolidated assessment")
    L.append("")
    L.append(f"- generated: {rep.get('generated', '')}")
    L.append(f"- hosts scanned: {s.get('hosts_scanned', 0)}")
    L.append(f"- SAST findings: {s.get('sast_findings', 0)}")
    L.append(f"- SCA known CVEs: {s.get('sca_cves', 0)}")
    L.append(f"- fuzz candidates: {s.get('fuzz_candidates', 0)}")
    L.append(f"- triage reports: {s.get('triage_reports', 0)}")
    L.append("")

    # Host scan
    L.append("## Hosts & services")
    L.append("")
    for h in rep.get("scan", []):
        svcs = (
            ", ".join(
                f"{x.get('port', '?')}/{x.get('service') or '?'}"
                for x in h.get("services", [])
            )
            or "—"
        )
        L.append(f"- `{h.get('address')}` OS={h.get('os') or '—'} services: {svcs}")
    L.append("")

    # SAST
    L.append("## Static analysis (SAST)")
    L.append("")
    if rep.get("sast"):
        for f in rep["sast"]:
            L.append(
                f"- **{f.get('severity')}** `{f.get('file')}:{f.get('line')}` "
                f"{f.get('name')} [{f.get('cwe')}]"
            )
    else:
        L.append("- none")
    L.append("")

    # SCA
    L.append("## Supply-chain (SCA)")
    L.append("")
    sca = rep.get("sca", {})
    cves = sca.get("cves", [])
    if cves:
        L.append("Known CVEs in dependencies:")
        for c in cves:
            L.append(f"- `{c}`")
    else:
        L.append("- no known CVEs (or no lockfile provided)")
    L.append("")

    # Fuzz
    L.append("## Fuzzing candidates")
    L.append("")
    if rep.get("fuzz"):
        for c in rep["fuzz"]:
            L.append(
                f"- {c.get('vector')}: **{c.get('signal')}** "
                f"{c.get('evidence', '')[:60]}"
            )
    else:
        L.append("- none")
    L.append("")

    # Triage
    L.append("## Triage & patch direction")
    L.append("")
    if rep.get("triage"):
        for t in rep["triage"]:
            L.append(
                f"- **{t.get('bug_class')}** ({t.get('cwe')}): "
                f"{t.get('minimized_trigger')}"
            )
    else:
        L.append("- none")
    L.append("")
    L.append("> authorized-scope only.")
    L.append("")
    return "\n".join(L)


def render_json(rep: dict[str, Any]) -> str:
    return json.dumps(rep, indent=2, default=str)
