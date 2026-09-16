# Endpoints for source analysis (SAST) and PoC/disclosure-skeleton generation.
# The operator uploads an archive or a git URL of software THEY are entitled to
# analyze; we scan its source for dangerous patterns. Exploit output is a
# minimal proof-of-concept scaffold intended for responsible disclosure and
# patching on systems you own — never a weapon to deploy against others.
import logging
import shutil
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile
from schemas import (
    SourceExploitRequest,
    SourceFinding,
    SourceScanRequest,
    SourceScanResult,
)
from services import ingest, sast

logger = logging.getLogger("h4k.routers.source")

router = APIRouter(prefix="/api/source")

# job store for long-running clones/scans
_source_jobs: dict[str, dict[str, Any]] = {}


@router.post("/scan", response_model=SourceScanResult)
async def scan_source(req: SourceScanRequest) -> SourceScanResult:
    """Scan a source project by git URL. (For archive upload use /scan/upload.)"""
    if not req.git_url:
        raise HTTPException(status_code=400, detail="git_url required")
    work = ingest.make_workdir()
    try:
        ingest.clone_git(req.git_url, work)
        root = ingest.find_source_root(work)
        scanner = sast.SASTScanner()
        findings = scanner.scan_dir(root)
        return _to_result(req.name, work, findings)
    except ingest.IngestError as exc:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/scan/upload", response_model=SourceScanResult)
async def scan_upload(
    file: UploadFile = File(...),  # noqa: B008 - FastAPI idiom for a required upload
) -> SourceScanResult:
    """Scan an uploaded source archive (.zip/.tar/.tar.gz)."""
    fname = file.filename or "source.bin"
    if not ingest.is_archive(fname):
        raise HTTPException(status_code=400, detail="must be .zip/.tar/.tar.gz")
    data = await file.read()
    work = ingest.make_workdir()
    try:
        ingest.extract_archive(data, fname, work)
        root = ingest.find_source_root(work)
        scanner = sast.SASTScanner()
        findings = scanner.scan_dir(root)
        return _to_result(ingest.normalize_source_name(fname), work, findings)
    except ingest.IngestError as exc:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/exploit", response_model=str)
def make_exploit(req: SourceExploitRequest) -> str:
    """Generate a proof-of-concept / disclosure skeleton for a finding."""
    finding = _finding_from(req)
    return sast.make_poc(finding)


@router.post("/exploit/download")
def download_exploit(req: SourceExploitRequest) -> Any:
    """Generate a PoC skeleton and return it as a downloadable file."""
    from fastapi.responses import PlainTextResponse

    poc = sast.make_poc(_finding_from(req))
    fname = f"h4k-poc-{req.rule_id or 'finding'}.txt"
    return PlainTextResponse(
        content=poc,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


def _to_result(name: str, work: Path, findings: list[sast.Finding]) -> SourceScanResult:
    root = ingest.find_source_root(work)
    nfiles = sum(1 for p in root.rglob("*") if p.is_file())
    return SourceScanResult(
        name=name,
        root=str(root),
        files_scanned=nfiles,
        findings=[_to_finding(f) for f in findings],
    )


def _to_finding(f: sast.Finding) -> SourceFinding:
    return SourceFinding(
        rule_id=f.rule_id,
        name=f.name,
        severity=f.severity,
        cwe=f.cwe,
        file=f.file,
        line=f.line,
        code=f.code,
        description=f.description,
    )


def _finding_from(req: SourceExploitRequest) -> sast.Finding:
    if req.finding:
        f = req.finding
        return sast.Finding(
            rule_id=f.rule_id,
            name=f.name,
            severity=f.severity,
            cwe=f.cwe,
            file=f.file,
            line=f.line,
            code=f.code,
            description=f.description,
        )
    # fall back to a lookup by rule id
    for rid, name, sev, cwe, _pat, desc in sast.RULES:
        if rid == req.rule_id:
            return sast.Finding(rid, name, sev, cwe, "", 0, "", desc)
    return sast.Finding(req.rule_id, "Unknown", "info", "CWE-710", "", 0, "", "")
