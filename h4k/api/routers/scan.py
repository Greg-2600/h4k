# REST endpoints for launching scans and polling job status.
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException

from schemas import Job, Report, ScanRequest
from services.report import build_report
from services.msfrpc import MsfClient
from services.scan_pipeline import ScanPipeline

logger = logging.getLogger("h4k.routers.scan")

router = APIRouter(prefix="/api")

# In-memory job store (single-lab deployment; fine for this project).
JOBS: dict[str, dict] = {}


def _get_msf() -> MsfClient:
    from app_state import msf_client
    return msf_client


def _run_scan(job: dict, req: ScanRequest):
    msf = _get_msf()
    pipeline = ScanPipeline(
        msf,
        progress=lambda msg, pct: _update(job, message=msg, progress=pct),
    )
    try:
        raw = pipeline.run(req, job["id"])
        report = build_report(
            target=req.target,
            mode=req.mode.value,
            hosts=raw.get("hosts", []),
            vulns=raw.get("vulns", []),
            notes=raw.get("notes", []),
        )
        _update(job, status="done", progress=100.0, report=report,
                message="scan complete")
    except Exception as exc:
        logger.exception("scan failed")
        _update(job, status="error", error=str(exc), message="scan failed")


def _update(job: dict, **kwargs):
    job.update(kwargs)
    job["updated"] = datetime.now(timezone.utc).isoformat()


@router.post("/scan", response_model=Job)
def create_scan(req: ScanRequest, background: BackgroundTasks):
    job = {
        "id": uuid.uuid4().hex[:12],
        "status": "queued",
        "progress": 0.0,
        "message": "queued",
        "report": None,
        "error": None,
        "created": datetime.now(timezone.utc).isoformat(),
    }
    JOBS[job["id"]] = job
    background.add_task(_run_scan, job, req)
    logger.info("scan job %s started for %s (%s)", job["id"], req.target, req.mode)
    return Job(**job)


@router.get("/jobs/{job_id}", response_model=Job)
def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return Job(**job)


@router.get("/report/{job_id}", response_model=Report)
def get_report(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    if job.get("report") is None:
        raise HTTPException(status_code=404, detail="report not ready")
    return job["report"]


@router.get("/health")
def health():
    msf = _get_msf()
    try:
        version = msf.client.core.version
        msf_ok = bool(version)
    except Exception:
        msf_ok = False
    msf_info = None
    try:
        msf_info = msf.client.core.version
    except Exception:
        pass
    return {"status": "ok", "msf": {"reachable": msf_ok, "version": msf_info},
            "jobs": len(JOBS)}
