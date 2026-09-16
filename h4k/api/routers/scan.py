# REST endpoints for launching scans and polling job status.
import logging
import uuid
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, BackgroundTasks, HTTPException
from schemas import Job, Report, ScanRequest
from services.cve_lookup import CveDb
from services.msfrpc import MsfClient
from services.report import build_report
from services.scan_pipeline import ScanPipeline

logger = logging.getLogger("h4k.routers.scan")

router = APIRouter(prefix="/api")

# In-memory job store (single-lab deployment; fine for this project).
JOBS: dict[str, dict[str, Any]] = {}


def _get_msf() -> MsfClient | None:
    from app_state import msf_client

    return msf_client


def _get_cve_db() -> CveDb | None:
    with suppress(Exception):
        from app_state import cve_db

        return cve_db
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
    pipeline = ScanPipeline(
        msf,
        progress=lambda msg, pct: _update(job, message=msg, progress=pct),
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
        )
        _update(
            job, status="done", progress=100.0, report=report, message="scan complete"
        )
    except Exception as exc:
        logger.exception("scan failed")
        _update(job, status="error", error=str(exc), message="scan failed")


def _update(job: dict[str, Any], **kwargs: Any) -> None:
    job.update(kwargs)
    job["updated"] = datetime.now(UTC).isoformat()


@router.post("/scan", response_model=Job)
def create_scan(req: ScanRequest, background: BackgroundTasks) -> Job:
    job: dict[str, Any] = {
        "id": uuid.uuid4().hex[:12],
        "status": "queued",
        "progress": 0.0,
        "message": "queued",
        "report": None,
        "error": None,
        "created": datetime.now(UTC).isoformat(),
    }
    job_id = job["id"]
    JOBS[job_id] = job
    background.add_task(_run_scan, job, req)
    logger.info("scan job %s started for %s (%s)", job_id, req.target, req.mode)
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
    }
