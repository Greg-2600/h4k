# REST endpoints for launching, caching, aborting, exporting and attacking.
import json
import logging
import time
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from schemas import AttackRequest, Job, Report, ScanRequest
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
_attack_cache: dict[str, list[dict[str, Any]]] = {}
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
    return f"{req.mode.value}::{req.target}"


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


@router.get("/jobs/{job_id}", response_model=Job)
def get_job(job_id: str) -> Job:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return Job(**job)


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

    svc = AttackService(msf, progress=lambda m, p: job.update(message=m))
    known = _attack_cache.get(req.target) or []
    try:
        attacks = svc.run(req, known)
        job["attacks"] = attacks
        job["status"] = "done"
    except Exception as exc:  # pragma: no cover - defensive
        job["status"] = "error"
        job["error"] = str(exc)


@router.get("/attack/{job_id}")
def attack_status(job_id: str) -> dict[str, Any]:
    job = _attack_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="attack job not found")
    return job


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
        "cache_entries": len(_scan_cache),
    }


def _report_markdown(report: Report) -> str:
    lines = [
        f"# h4k report — {report.target}",
        "",
        f"- **mode**: {report.mode.value}",
        f"- **generated**: {report.created_at}",
        "",
        "## Hosts",
        "",
    ]
    for h in report.hosts:
        svcs = ", ".join(f"{s.port}/{s.service or '?'}" for s in h.services) or "-"
        lines.append(f"- `{h.address}` OS={h.os or '-'} services: {svcs}")
    lines += ["", "## Vulnerabilities", ""]
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
