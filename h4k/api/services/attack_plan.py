# Attack paths to declared objectives, plus an honest coverage ledger.
#
# The engagement graph knows what exists (hosts/services/verified credentials)
# and the finding ledger knows what was proven. This module answers the question
# a report actually needs: "from a foothold we already have, what is the shortest
# path to the thing the operator cares about, and which finding matters?"
#
# It is intentionally a graph over *verified* access. A credential edge exists
# only where a login actually succeeded (`cred_access`), and a finding counts as
# a foothold only when it is critical/high and evidence-backed or verified.
# Nothing is inferred from "both hosts run SSH". Direct host-to-host connectivity
# is not invented either; lateral edges come from credential reuse.
import heapq
import logging
from typing import Any

from services.engagement import (
    COVERAGE_OUTCOMES,
    CRITICALITIES,
    EngagementStore,
)

logger = logging.getLogger("h4k.attack_paths")

CRITICALITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SERVICE_TECHNIQUE = {
    "ssh": "T1021.004",
    "smb": "T1021.002",
    "rdp": "T1021.001",
    "winrm": "T1021.006",
    "wmi": "T1047",
    "ldap": "T1087.002",
    "mssql": "T1078",
    "http": "T1078",
}
COVERAGE_GAP_OUTCOMES = {"needs_follow_up", "not_tested"}


def _technique(service: str | None) -> str:
    return SERVICE_TECHNIQUE.get((service or "").lower(), "T1078")


class AttackPathService:
    def __init__(
        self,
        store: EngagementStore | None = None,
        findings: Any | None = None,
    ) -> None:
        self.store = store or EngagementStore()
        if findings is None:
            from services.findings import FindingStore

            findings = FindingStore()
        self.findings = findings

    # -- graph --------------------------------------------------------------
    def evaluate(
        self, engagement_id: str, start_hosts: list[str] | None = None
    ) -> dict[str, Any]:
        engagement = self.store.get_engagement(engagement_id)
        if engagement is None:
            raise ValueError("engagement not found")
        creds = self.store.credentials(engagement_id)
        objectives = self.store.objectives(engagement_id)
        coverage = self.store.coverage(engagement_id)
        findings = self.findings.list_findings(engagement_id=engagement_id, limit=500)
        open_findings = [
            f for f in findings if f.get("status") not in {"fixed", "false_positive"}
        ]
        by_host: dict[str, list[dict[str, Any]]] = {}
        for finding in open_findings:
            host = str(finding.get("host") or "")
            if host:
                by_host.setdefault(host, []).append(finding)

        footholds: dict[str, list[dict[str, Any]]] = {}
        for cred in creds:
            if not cred.get("verified"):
                continue
            for access in cred.get("hosts") or []:
                host = str(access.get("host") or "")
                if not host:
                    continue
                footholds.setdefault(host, []).append(
                    {
                        "type": "credential",
                        "detail": f"{cred.get('user')}@{cred.get('service') or 'any'}",
                        "user": cred.get("user"),
                        "service": cred.get("service"),
                        "port": access.get("port"),
                        "verified": True,
                    }
                )
        for host, host_findings in by_host.items():
            for finding in host_findings:
                if finding.get("severity") not in {"critical", "high"}:
                    continue
                if not (finding.get("verified") or finding.get("evidence_backed")):
                    continue
                footholds.setdefault(host, []).append(
                    {
                        "type": "finding",
                        "detail": finding.get("title"),
                        "finding_id": finding.get("id"),
                        "severity": finding.get("severity"),
                        "verified": bool(finding.get("verified")),
                    }
                )

        if start_hosts:
            wanted = {str(h) for h in start_hosts if h}
            footholds = {h: r for h, r in footholds.items() if h in wanted}
            if not footholds:
                # A named start host with no proven foothold is still a useful
                # answer: there is no path from it.
                pass

        adjacency: dict[str, list[tuple[str, float, dict[str, Any]]]] = {}
        for cred in creds:
            if not cred.get("verified"):
                continue
            access_hosts = [
                str(a.get("host")) for a in (cred.get("hosts") or []) if a.get("host")
            ]
            if len(access_hosts) < 2:
                continue
            technique = _technique(cred.get("service"))
            for source in access_hosts:
                for target in access_hosts:
                    if source == target:
                        continue
                    adjacency.setdefault(source, []).append(
                        (
                            target,
                            1.0,
                            {
                                "type": "credential_reuse",
                                "from": source,
                                "to": target,
                                "user": cred.get("user"),
                                "service": cred.get("service"),
                                "technique": technique,
                            },
                        )
                    )

        paths = []
        reachable_ids: set[str] = set()
        for objective in objectives:
            target = str(objective["host"])
            best: dict[str, Any] | None = None
            for foothold in footholds:
                if foothold == target:
                    candidate = {
                        "objective": objective,
                        "foothold": foothold,
                        "foothold_reasons": footholds[foothold],
                        "hops": [],
                        "cost": 0.0,
                        "techniques": [],
                        "findings": by_host.get(target, []),
                        "evidence": [],
                    }
                else:
                    route = _dijkstra(adjacency, foothold, target)
                    if route is None:
                        continue
                    hops, cost = route
                    hosts_on_path = [foothold, *[hop["to"] for hop in hops]]
                    findings_on_path = [
                        f for host in hosts_on_path for f in by_host.get(host, [])
                    ]
                    candidate = {
                        "objective": objective,
                        "foothold": foothold,
                        "foothold_reasons": footholds[foothold],
                        "hops": hops,
                        "cost": round(cost, 2),
                        "techniques": sorted(
                            {
                                hop.get("technique", "")
                                for hop in hops
                                if hop.get("technique")
                            }
                            | {
                                str(f.get("technique"))
                                for f in findings_on_path
                                if f.get("technique")
                            }
                        ),
                        "findings": findings_on_path,
                        "evidence": _evidence(self.findings, findings_on_path),
                    }
                if best is None or (
                    candidate["cost"],
                    max(
                        (
                            SEVERITY_RANK.get(str(f.get("severity")), 9)
                            for f in candidate["findings"]
                        ),
                        default=9,
                    ),
                ) < (
                    best["cost"],
                    max(
                        (
                            SEVERITY_RANK.get(str(f.get("severity")), 9)
                            for f in best["findings"]
                        ),
                        default=9,
                    ),
                ):
                    best = candidate
            if best is None:
                continue
            reachable_ids.add(str(objective["host"]))
            best["objective_criticality"] = objective.get("criticality", "high")
            best["finding_count"] = len(best["findings"])
            best["techniques"] = sorted(
                set(best["techniques"])
                | {
                    str(f.get("technique"))
                    for f in best["findings"]
                    if f.get("technique")
                }
            )
            best["verified_findings"] = sum(
                1 for f in best["findings"] if f.get("verified")
            )
            paths.append(best)
        paths.sort(
            key=lambda p: (
                CRITICALITY_RANK.get(p["objective_criticality"], 9),
                p["cost"],
                max(
                    (
                        SEVERITY_RANK.get(str(f.get("severity")), 9)
                        for f in p["findings"]
                    ),
                    default=9,
                ),
                p["objective"]["host"],
            )
        )
        for index, path in enumerate(paths, start=1):
            path["rank"] = index
            path["chain"] = " → ".join(
                [
                    path["foothold"],
                    *[hop["to"] for hop in path["hops"]],
                ]
            )
            path["risk"] = _path_risk(path)

        coverage_summary = _coverage_summary(coverage, objectives)
        return {
            "ok": True,
            "engagement_id": engagement_id,
            "engagement": engagement.get("name", ""),
            "objectives": objectives,
            "footholds": [
                {"host": host, "reasons": reasons}
                for host, reasons in sorted(footholds.items())
            ],
            "paths": paths,
            "reachable_objectives": sorted(reachable_ids),
            "unreachable_objectives": [
                o for o in objectives if str(o["host"]) not in reachable_ids
            ],
            "coverage": coverage_summary,
            "risk": (
                "critical"
                if any(p["risk"] == "critical" for p in paths)
                else (
                    "high"
                    if any(p["risk"] == "high" for p in paths)
                    else "medium" if paths else "low"
                )
            ),
            "note": (
                "Paths use verified credential access and evidence-backed critical/"
                "high findings only; absence of a path is not proof of isolation."
            ),
        }

    # -- reporting ----------------------------------------------------------
    def report_section(self, engagement_id: str) -> str:
        result = self.evaluate(engagement_id)
        lines = ["## Attack paths & coverage", ""]
        if not result["objectives"]:
            lines.append(
                "No objectives declared. Declare a crown jewel (DC, DB, file server) "
                "to rank paths against it."
            )
            lines.append("")
        else:
            lines.append("| Objective | Criticality | Reachable | Best path |")
            lines.append("|---|---|---|---|")
            best_by_host = {str(p["objective"]["host"]): p for p in result["paths"]}
            for objective in result["objectives"]:
                host = str(objective["host"])
                best = best_by_host.get(host)
                lines.append(
                    "| {label} (`{host}`) | {crit} | {reach} | {path} |".format(
                        label=_md(str(objective.get("label") or host)),
                        host=host,
                        crit=objective.get("criticality", "high"),
                        reach="yes" if best else "no",
                        path=(
                            f"{best['chain']} (cost {best['cost']})" if best else "—"
                        ),
                    )
                )
            lines.append("")
            for path in result["paths"]:
                lines.append(
                    f"### #{path['rank']} {path['chain']} → "
                    f"{path['objective']['host']}"
                )
                lines.append(
                    f"- objective: **{path['objective_criticality']}** · "
                    f"cost `{path['cost']}` · risk **{path['risk']}**"
                )
                if path["techniques"]:
                    lines.append(
                        "- ATT&CK: " + ", ".join(f"`{t}`" for t in path["techniques"])
                    )
                if path["findings"]:
                    lines.append(
                        "- findings: "
                        + ", ".join(
                            f"`{f['id']}` {f['severity']} {_md(str(f['title']))}"
                            for f in path["findings"][:10]
                        )
                    )
                if path["evidence"]:
                    lines.append(
                        "- evidence: "
                        + ", ".join(
                            f"`{e['finding_id']}/{e['sha256'][:12]}…`"
                            for e in path["evidence"][:10]
                        )
                    )
                lines.append("")
            if result["unreachable_objectives"]:
                lines.append("### Unreachable objectives")
                for objective in result["unreachable_objectives"]:
                    lines.append(
                        f"- `{objective['host']}` ({objective.get('criticality')}): "
                        "no verified path from a current foothold"
                    )
                lines.append("")
        coverage = result["coverage"]
        lines.append(
            "### Coverage\n\n"
            f"{coverage['entries']} entries · {coverage['tested']} tested · "
            f"{coverage['gaps']} gap(s)"
        )
        if coverage["by_outcome"]:
            lines.append("")
            for outcome, count in sorted(coverage["by_outcome"].items()):
                lines.append(f"- `{outcome}`: {count}")
        if coverage["gap_entries"]:
            lines.append("")
            for gap in coverage["gap_entries"][:20]:
                lines.append(
                    f"- gap `{gap['host']}` {gap.get('port') or ''} "
                    f"{gap['risk_area']}: {gap['outcome']}"
                )
        lines.append("")
        return "\n".join(lines)


def _evidence(
    findings_store: Any, findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for finding in findings[:20]:
        try:
            detail = findings_store.get_finding(str(finding["id"]))
        except Exception:  # nosec B112 - evidence enrichment is best-effort
            continue
        for item in detail.get("evidence", [])[:5]:
            out.append(
                {
                    "finding_id": finding["id"],
                    "evidence_id": item.get("id"),
                    "kind": item.get("kind"),
                    "sha256": str(item.get("sha256") or ""),
                }
            )
    return out


def _dijkstra(
    adjacency: dict[str, list[tuple[str, float, dict[str, Any]]]],
    start: str,
    target: str,
) -> tuple[list[dict[str, Any]], float] | None:
    dist: dict[str, float] = {start: 0.0}
    previous: dict[str, tuple[str, dict[str, Any]]] = {}
    heap: list[tuple[float, str]] = [(0.0, start)]
    while heap:
        cost, node = heapq.heappop(heap)
        if node == target:
            hops: list[dict[str, Any]] = []
            while node in previous:
                parent, edge = previous[node]
                hops.append(edge)
                node = parent
            hops.reverse()
            return hops, cost
        if cost > dist.get(node, float("inf")):
            continue
        for neighbour, weight, edge in adjacency.get(node, []):
            new_cost = cost + weight
            if new_cost < dist.get(neighbour, float("inf")):
                dist[neighbour] = new_cost
                previous[neighbour] = (node, edge)
                heapq.heappush(heap, (new_cost, neighbour))
    return None


def _coverage_summary(
    coverage: list[dict[str, Any]], objectives: list[dict[str, Any]]
) -> dict[str, Any]:
    by_outcome: dict[str, int] = {}
    covered_hosts: set[str] = set()
    gaps: list[dict[str, Any]] = []
    tested_outcomes = {"reported", "no_issue_found", "ruled_out", "not_applicable"}
    for entry in coverage:
        outcome = str(entry.get("outcome") or "")
        by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        covered_hosts.add(str(entry.get("host") or ""))
        if outcome in COVERAGE_GAP_OUTCOMES:
            gaps.append(entry)
    for objective in objectives:
        host = str(objective["host"])
        if host not in covered_hosts:
            gaps.append(
                {
                    "host": host,
                    "port": 0,
                    "risk_area": "objective",
                    "outcome": "not_tested",
                    "reason": "objective has no coverage record",
                }
            )
    return {
        "entries": len(coverage),
        "tested": sum(
            1 for entry in coverage if entry.get("outcome") in tested_outcomes
        ),
        "gaps": len(gaps),
        "by_outcome": by_outcome,
        "gap_entries": gaps,
        "outcomes": list(COVERAGE_OUTCOMES),
        "criticalities": list(CRITICALITIES),
    }


def _path_risk(path: dict[str, Any]) -> str:
    severities = {str(f.get("severity")) for f in path.get("findings", [])}
    if path.get("objective_criticality") == "critical" or "critical" in severities:
        return "critical"
    if path.get("objective_criticality") == "high" or "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    return "low"


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")[:300]
