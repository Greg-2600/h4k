# Endpoints for source analysis (SAST) and PoC/disclosure-skeleton generation.
# The operator uploads an archive or a git URL of software THEY are entitled to
# analyze; we scan its source for dangerous patterns. Exploit output is a
# minimal proof-of-concept scaffold intended for responsible disclosure and
# patching on systems you own — never a weapon to deploy against others.
import json
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, UploadFile
from schemas import (
    AiLoopResult,
    AiRequest,
    AiResult,
    CustomRuleRequest,
    SanitizerDiffRequest,
    SanitizerDiffResult,
    ScaResult,
    SourceExploitRequest,
    SourceFinding,
    SourceScanRequest,
    SourceScanResult,
    TriageRequest,
    TriageResult,
)
from services import (
    ai as ai_service,
    ingest,
    merged_report,
    rules as rules_service,
    sast,
    sca as sca_service,
    semgrep,
    triage as triage_service,
)

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


@router.post("/sanitizer/diff", response_model=SanitizerDiffResult)
def sanitizer_diff(req: SanitizerDiffRequest) -> SanitizerDiffResult:
    """Compare ASan vs UBSan vs MSan on one pasted report (offline).

    Classifies the report, states per-family would-detect verdicts from
    a coverage table, names the blind spots, and recommends the single
    best confirming rebuild. Sandbox returns a canned diff.
    """
    from services import sandbox as sandbox_mode
    from services.sanitizer_diff import diff_report, sandbox_result

    try:
        if not (req.report or "").strip():
            raise ValueError("report required (paste sanitizer output)")
        result = sandbox_result() if sandbox_mode.enabled() else diff_report(req.report)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return SanitizerDiffResult(
        bug_class=result.get("class", "unknown"),
        **{k: v for k, v in result.items() if k != "class"},
    )


@router.post("/exploit")
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


@router.post("/sca", response_model=ScaResult)
def software_composition(req: SourceScanRequest) -> ScaResult:
    """Software Composition Analysis: SBOM + known-CVE check on the source."""
    if not req.git_url:
        raise HTTPException(status_code=400, detail="git_url required")
    work = ingest.make_workdir()
    try:
        ingest.clone_git(req.git_url, work)
        root = ingest.find_source_root(work)
    except ingest.IngestError as exc:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        res = sca_service.sca_scan(root, with_sbom=True)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return ScaResult(
        cves=res.get("cves", []),
        vulnerabilities=res.get("vulnerabilities", []),
        packages=res.get("packages", []),
        sbom_available=bool(res.get("sbom_available")),
        secrets=res.get("secrets", []),
        licenses=res.get("licenses", []),
    )


@router.get("/sca/git")
def sca_by_url(git_url: str) -> ScaResult:
    return software_composition(SourceScanRequest(git_url=git_url))


@router.get("/sca/sbom")
def sca_sbom_download(git_url: str) -> Any:
    """Build an SBOM for a git URL and return it as a downloadable CycloneDX file."""
    from fastapi.responses import PlainTextResponse

    work = ingest.make_workdir()
    try:
        ingest.clone_git(git_url, work)
        root = ingest.find_source_root(work)
        sbom = sca_service.generate_sbom(root)
    except ingest.IngestError as exc:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        if not sbom or not sbom.exists():
            raise HTTPException(status_code=400, detail="could not generate SBOM")
        content = sbom.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return PlainTextResponse(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="sbom.cdx.json"'},
    )


@router.get("/sca/github-cves")
def search_github_cves(
    repo: str,
    ecosystem: str = "pip",
    page: int = 1,
    per_page: int = 30,
) -> dict[str, Any]:
    """Search GitHub Advisory Database for CVEs affecting a repo's dependencies.

    - **repo**: Full repo slug (e.g. `octocat/Hello-World` or `owner/project`)
    - **ecosystem**: Package ecosystem to query (`pip`, `npm`, `go`, `cargo`, `nuget`, `rubygems`)
    - **page**: Result page number (default 1)
    - **per_page**: Results per page (default 30, max 100)

    Returns advisories with GHSA ID, CVE ID, severity, description, and fixed versions.
    """
    import urllib.request

    url = (
        f"https://api.github.com/advisories"
        f"?type=reviewed"
        f"&ecosystem={ecosystem}"
        f"&severity=critical,high,medium"
        f"&page={page}"
        f"&per_page={per_page}"
    )
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "h4k-security-platform/1.0")
    # Optionally use GITHUB_TOKEN if available
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            data = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=exc.code,
            detail=f"GitHub API error: {exc.reason}",
        ) from exc
    except urllib.error.URLError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not reach GitHub: {exc.reason}",
        ) from exc

    advisories = []
    for item in data if isinstance(data, list) else data.get("advisories", []):
        advisories.append(
            {
                "ghsa_id": item.get("ghsa_id"),
                "cve_id": item.get("cve_id"),
                "severity": item.get("severity"),
                "summary": item.get("summary", ""),
                "description": item.get("description", ""),
                "published_at": item.get("published_at"),
                "html_url": item.get("html_url"),
                "identifiers": item.get("identifiers", []),
                "references": item.get("references", []),
                "vulnerabilities": item.get("vulnerabilities", []),
                "weaknesses": item.get("weaknesses", []),
                "fixes": (
                    [
                        {
                            "version": f.get("vulnerable_version_range", ""),
                            "first_patched_version": f.get("first_patched_version"),
                        }
                        for f in item.get("vulnerabilities", [])
                    ]
                    if item.get("vulnerabilities")
                    else []
                ),
            }
        )

    return {
        "repo": repo,
        "ecosystem": ecosystem,
        "count": len(advisories),
        "page": page,
        "per_page": per_page,
        "advisories": advisories,
    }


@router.get("/sca/map")
def sca_supply_chain_map(git_url: str) -> dict[str, Any]:
    """Supply-chain map: dependency graph + per-package CVE reachability.

    Returns {components, graph{nodes,edges}, summary{n,cves}} from the SBOM,
    annotated with known CVEs per package from osv-scanner.
    """
    work = ingest.make_workdir()
    try:
        ingest.clone_git(git_url, work)
        root = ingest.find_source_root(work)
    except ingest.IngestError as exc:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        res = sca_service.sca_scan(root, with_sbom=True)
        sbom_path = res.get("sbom_path")
        if not sbom_path or not Path(sbom_path).exists():
            return {"error": "no SBOM generated (no manifest/lockfile present)"}
        from services.sbom import build_supply_chain_map

        return build_supply_chain_map(Path(sbom_path), res.get("pkg_cves", {}))
    finally:
        shutil.rmtree(work, ignore_errors=True)


@router.post("/triage", response_model=TriageResult)
def analyze_crash(req: TriageRequest) -> TriageResult:
    """Analyze a fuzzer crash candidate or SAST finding -> triage + patch hint."""
    finding = _finding_from_src(req.finding) if req.finding else None
    if not req.candidate and finding:
        candidate = finding.code or str(finding.line)
    else:
        candidate = req.candidate
    report = triage_service.build_triage(candidate, finding)
    return TriageResult(**report.to_dict())


@router.post("/ai", response_model=AiResult)
def ai_analysis(req: AiRequest) -> AiResult:
    """Ask the configured LLM for a root-cause + patch candidate."""
    result = ai_service.ai_analyze(req.text, model_override=req.model)
    return AiResult(**result)


@router.post("/ai/loop", response_model=AiLoopResult)
def ai_full_loop(req: AiRequest) -> AiLoopResult:
    """AI full-loop: root cause + patch candidate + verify/re-fuzz steps."""
    from services.ai_loop import ai_full_loop

    result = ai_full_loop(req.text, model_override=req.model)
    return AiLoopResult(
        ok=result["ok"],
        provider=result.get("provider", ""),
        raw=result.get("raw", ""),
        error=result.get("error"),
        parsed=result.get("parsed", {}),
    )


@router.post("/rules/test")
def test_custom_rule(req: CustomRuleRequest) -> dict[str, Any]:
    """Validate a custom Semgrep-style rule against sample code."""
    return semgrep.test_rule(req)


@router.get("/rules")
def list_custom_rules() -> dict[str, Any]:
    """List saved custom rules."""
    return {"rules": rules_service.list_rules()}


@router.post("/rules/save")
def save_custom_rule(req: CustomRuleRequest) -> dict[str, Any]:
    """Save a user-authored rule to the rule library."""
    rule = {
        "rule_id": req.rule_id,
        "name": req.name,
        "severity": req.severity,
        "languages": req.languages,
        "pattern": req.pattern,
        "message": req.message,
        "cwe": req.cwe,
    }
    try:
        saved = rules_service.save_rule(rule)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "rule": saved}


@router.delete("/rules/{rule_id}")
def delete_custom_rule(rule_id: str) -> dict[str, Any]:
    """Delete a saved rule by id."""
    removed = rules_service.delete_rule(rule_id)
    return {"ok": removed, "rule_id": rule_id}


@router.post("/rules/run")
def run_custom_rules(req: SourceScanRequest) -> dict[str, Any]:
    """Run all saved custom rules over a clonable git URL."""
    if not req.git_url:
        raise HTTPException(status_code=400, detail="git_url required")
    work = ingest.make_workdir()
    try:
        ingest.clone_git(req.git_url, work)
        root = ingest.find_source_root(work)
    except ingest.IngestError as exc:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    rules = rules_service.list_rules()
    findings: list[dict[str, Any]] = []
    for r in rules:
        findings.extend(rules_service.run_rule_via_regex(r, root))
    shutil.rmtree(work, ignore_errors=True)
    return {"findings": findings, "count": len(findings), "rules_run": len(rules)}


@router.post("/triage/minimize")
def minimize(req: TriageRequest) -> dict[str, Any]:
    """Best-effort minimize of a crash candidate.

    Triage has no crash artifact/harness, so this usually reports that it did
    NOT reduce the input. Real reduction is `POST /api/fuzz/minimize`.
    """
    trigger, reduced, note = triage_service._attempt_minimize(
        req.candidate, req.finding.cwe if req.finding else "unknown"
    )
    return {
        "original": req.candidate,
        "minimized": trigger,
        "reduced": reduced,
        "note": note,
    }


def _finding_from_src(f: SourceFinding) -> sast.Finding:
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
    from services import sanitizer

    return SourceFinding(
        rule_id=f.rule_id,
        name=f.name,
        severity=f.severity,
        cwe=f.cwe,
        file=f.file,
        line=f.line,
        code=f.code,
        description=f.description,
        sanitizer=sanitizer.verify_plan(f.cwe, rule_id=f.rule_id, file=f.file),
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


@router.get("/ai/models")
def ai_models() -> dict[str, Any]:
    """List locally available Ollama models + current provider/model."""
    return {
        "provider": ai_service._provider(),
        "model": ai_service._model(),
        "ollama_reachable": ai_service._probe_ollama(),
        "models": ai_service.ollama_models(),
    }


@router.post("/report/merge")
def build_merged_report(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Merge provided scan/SAST/SCA/fuzz/triage sections into one structured
    report (the deliverable). Callers pass in their collected findings."""
    body = body or {}
    rep = merged_report.build_merged_report(
        scan=body.get("scan"),
        sast=body.get("sast"),
        sca=body.get("sca"),
        fuzz=body.get("fuzz"),
        triage=body.get("triage"),
        watch=body.get("watch"),
    )
    return rep


@router.post("/report/md")
def report_markdown(body: dict[str, Any] | None = None) -> str:
    """Merge findings and return the assessment as markdown."""
    body = body or {}
    rep = merged_report.build_merged_report(
        scan=body.get("scan"),
        sast=body.get("sast"),
        sca=body.get("sca"),
        fuzz=body.get("fuzz"),
        triage=body.get("triage"),
        watch=body.get("watch"),
    )
    return merged_report.render_markdown(rep)


@router.get("/report/md")
def report_markdown_get() -> str:
    return merged_report.render_markdown(merged_report.build_merged_report())


@router.post("/fuzz/minimize")
def fuzz_minimize(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Given a fuzzer binary + crash artifacts, minimize them (libFuzzer).
    body = {cmd: [binary, ...flags], crashes: [paths]}."""
    from services.fuzzer import LabFuzzer

    body = body or {}
    cmd = body.get("cmd") or []
    crashes = body.get("crashes") or []
    res = LabFuzzer().minimize_crash(cmd, crashes)
    return {"minimized": res, "note": "libFuzzer -minimize_crash=1"}


@router.post("/ossfuzz")
def ossfuzz_runner(body: dict[str, Any] | None = None) -> dict[str, Any]:
    """Clone a repo and run an OSS-Fuzz-style auto run: build with ASan/UBSan,
    fuzz (libFuzzer) for N seconds, return crash leads.
    body = {git_url, target, build_cmd?, seconds?}."""
    from services.ossfuzz import OssFuzzRunner

    body = body or {}
    git_url = body.get("git_url")
    if not git_url:
        raise HTTPException(status_code=400, detail="git_url required")
    work = ingest.make_workdir()
    try:
        ingest.clone_git(git_url, work)
        root = ingest.find_source_root(work)
    except ingest.IngestError as exc:
        shutil.rmtree(work, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        res = OssFuzzRunner().run(
            repo=root,
            build_cmd=body.get("build_cmd"),
            fuzz_bin=body.get("target") or "parse_fuzzer",
            seconds=int(body.get("seconds", 10)),
        )
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return res
