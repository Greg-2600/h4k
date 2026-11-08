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
    CiGateRequest,
    CiGateResult,
    CustomRuleRequest,
    MultilangScanRequest,
    MultilangScanResult,
    ReachabilityRequest,
    ReachabilityResult,
    SanitizerDiffRequest,
    SanitizerDiffResult,
    SarifExportRequest,
    SarifImportRequest,
    SarifImportResult,
    SastDeltaRequest,
    SastDeltaResult,
    ScaResult,
    SecretsScanRequest,
    SecretsScanResult,
    SourceExploitRequest,
    SourceFinding,
    SourceScanRequest,
    SourceScanResult,
    SuppressMatchRequest,
    SuppressMatchResult,
    TaintScanRequest,
    TaintScanResult,
    TriageRequest,
    TriageResult,
    VerifyFixRequest,
    VerifyFixResult,
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


@router.post("/sarif/export")
def sarif_export(req: SarifExportRequest) -> dict[str, Any]:
    """Export pasted h4k findings to SARIF 2.1.0 (offline).

    Severities map critical|high→error, medium→warning, low→note,
    info→none; CWEs ride in rule properties. Sandbox returns a canned
    round-trip.
    """
    from services import sandbox as sandbox_mode
    from services.sarif_exchange import h4k_to_sarif, sandbox_roundtrip

    if not isinstance(req.findings, list) or not req.findings:
        raise HTTPException(
            status_code=400, detail="findings required (paste h4k findings JSON)"
        )
    sarif = sandbox_roundtrip()["sarif"] if sandbox_mode.enabled() else None
    if sarif is None:
        try:
            sarif = h4k_to_sarif(req.findings, tool_name=req.tool_name or "h4k-sast")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"sarif": sarif}


@router.post("/sarif/import", response_model=SarifImportResult)
def sarif_import(req: SarifImportRequest) -> SarifImportResult:
    """Import outside SARIF (e.g. Semgrep `--sarif`) into h4k findings.

    Rules resolve against each run's driver for names + CWEs; the
    producing tool is noted, never relabeled. Malformed results are
    reported per index, never silently dropped. Sandbox returns canned
    findings.
    """
    import json as json_lib

    from services import sandbox as sandbox_mode
    from services.sarif_exchange import sandbox_roundtrip, sarif_to_h4k

    doc = req.sarif
    if isinstance(doc, str):
        if not doc.strip():
            raise HTTPException(
                status_code=400, detail="sarif required (paste SARIF JSON)"
            )
        try:
            doc = json_lib.loads(doc)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"sarif is not JSON: {exc}"
            ) from exc
    if not isinstance(doc, dict) or not doc:
        raise HTTPException(status_code=400, detail="sarif required (paste SARIF JSON)")
    if sandbox_mode.enabled():
        doc = {"version": "2.1.0", "runs": sandbox_roundtrip()["sarif"]["runs"]}
    try:
        result = sarif_to_h4k(doc)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    findings: list[SourceFinding] = []
    for finding in result.get("findings", []):
        try:
            findings.append(SourceFinding(**finding))
        except ValueError:
            continue
    return SarifImportResult(
        findings=findings,
        finding_count=len(findings),
        skipped=result.get("skipped", 0),
        errors=result.get("errors", []),
        tool=result.get("tool", ""),
    )


@router.post("/secrets/scan", response_model=SecretsScanResult)
def secrets_scan(req: SecretsScanRequest) -> SecretsScanResult:
    """Scan pasted sources for hardcoded secrets, minus the noise.

    Findings already in `baseline` (fingerprints or finding dicts)
    are reported, not repeated; `allowlist` regexes suppress matches
    with the matching pattern recorded. Only `new` findings ledger as
    vulns on the labeled host when `engagement_id` is set
    (scope-enforced). Sandbox returns a canned new/baselined/
    allowlisted split.
    """
    from services import sandbox as sandbox_mode
    from services.secret_baseline import (
        audit,
        sandbox_result,
        to_ledger,
        validate_allowlist,
    )

    files = list(req.files or [])
    if req.bundle and req.bundle.strip():
        from services.taint_pack import parse_bundle

        files.extend(parse_bundle(req.bundle))
    if not files:
        raise HTTPException(status_code=400, detail="bundle or files required")
    try:
        validate_allowlist(req.allowlist)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    host = (req.host or "127.0.0.1").strip() or "127.0.0.1"
    if sandbox_mode.enabled():
        result = sandbox_result()
    else:
        try:
            result = audit(files, baseline=req.baseline, allowlist=req.allowlist)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    ingested = 0
    skipped: list[str] = []
    if req.engagement_id:
        from routers.engagement import get_store
        from services.engagement import ScopeError

        store = get_store()
        if not store.get_engagement(req.engagement_id):
            raise HTTPException(status_code=404, detail="engagement not found")
        for entry in to_ledger(host, "secrets-baseline", result.get("new") or []):
            try:
                ingested += store.record_vuln(req.engagement_id, entry["host"], entry)
            except ScopeError:
                if entry["host"] not in skipped:
                    skipped.append(entry["host"])
    return SecretsScanResult(
        **{
            **result,
            "ingested": ingested,
            "skipped_out_of_scope": skipped,
        }
    )


@router.post("/taint/scan", response_model=TaintScanResult)
def taint_scan(req: TaintScanRequest) -> TaintScanResult:
    """Run the taint rules pack over pasted sources (offline).

    `bundle` (=== path === blocks) or `files` — both stay server-side
    for this call only. `engagement_id` ledgers findings as vulns on
    the labeled host (scope-enforced). Sandbox returns canned findings.
    """
    from services import sandbox as sandbox_mode
    from services.taint_pack import parse_bundle, sandbox_result, scan_files, to_ledger

    files = list(req.files or [])
    if req.bundle and req.bundle.strip():
        files.extend(parse_bundle(req.bundle))
    if not files:
        raise HTTPException(status_code=400, detail="bundle or files required")
    host = (req.host or "127.0.0.1").strip() or "127.0.0.1"
    if sandbox_mode.enabled():
        result = sandbox_result()
    else:
        try:
            result = scan_files(files)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    ingested = 0
    skipped: list[str] = []
    if req.engagement_id:
        from routers.engagement import get_store
        from services.engagement import ScopeError

        store = get_store()
        if not store.get_engagement(req.engagement_id):
            raise HTTPException(status_code=404, detail="engagement not found")
        for entry in to_ledger(host, "taint-pack", result.get("findings") or []):
            try:
                ingested += store.record_vuln(req.engagement_id, entry["host"], entry)
            except ScopeError:
                if entry["host"] not in skipped:
                    skipped.append(entry["host"])
    return TaintScanResult(
        **{
            **result,
            "ingested": ingested,
            "skipped_out_of_scope": skipped,
        }
    )


@router.post("/sast/multilang", response_model=MultilangScanResult)
def multilang_scan(req: MultilangScanRequest) -> MultilangScanResult:
    """Run the Go+Rust source→sink pack over pasted sources (offline).

    `bundle` (=== path === blocks) or `files` — both stay server-side
    for this call only. `engagement_id` ledgers findings as vulns on
    the labeled host (scope-enforced). Sandbox returns canned findings.
    """
    from services import sandbox as sandbox_mode
    from services.multilang_sast import sandbox_result, scan_files, to_ledger
    from services.taint_pack import parse_bundle

    files = list(req.files or [])
    if req.bundle and req.bundle.strip():
        files.extend(parse_bundle(req.bundle))
    if not files:
        raise HTTPException(status_code=400, detail="bundle or files required")
    host = (req.host or "127.0.0.1").strip() or "127.0.0.1"
    if sandbox_mode.enabled():
        result = sandbox_result()
    else:
        try:
            result = scan_files(files)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    ingested = 0
    skipped: list[str] = []
    if req.engagement_id:
        from routers.engagement import get_store
        from services.engagement import ScopeError

        store = get_store()
        if not store.get_engagement(req.engagement_id):
            raise HTTPException(status_code=404, detail="engagement not found")
        for entry in to_ledger(host, "multilang-sast", result.get("findings") or []):
            try:
                ingested += store.record_vuln(req.engagement_id, entry["host"], entry)
            except ScopeError:
                if entry["host"] not in skipped:
                    skipped.append(entry["host"])
    return MultilangScanResult(
        **{
            **result,
            "ingested": ingested,
            "skipped_out_of_scope": skipped,
        }
    )


@router.post("/reachability", response_model=ReachabilityResult)
def reachability(req: ReachabilityRequest) -> ReachabilityResult:
    """Build an import graph and report unreachable files (offline).

    `bundle` (=== path === blocks) or `files`. Entries pin the roots;
    without them roots are guessed and flagged. Advisory output only —
    dead code is not a vuln, so nothing ledgers. Sandbox returns a
    canned graph.
    """
    from services import sandbox as sandbox_mode
    from services.reachability import analyze, sandbox_result
    from services.taint_pack import parse_bundle

    files = list(req.files or [])
    if req.bundle and req.bundle.strip():
        files.extend(parse_bundle(req.bundle))
    if not files:
        raise HTTPException(status_code=400, detail="bundle or files required")
    if sandbox_mode.enabled():
        return ReachabilityResult(**sandbox_result())
    try:
        return ReachabilityResult(**analyze(files, entries=req.entries or None))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/ci/gate", response_model=CiGateResult)
def ci_gate(req: CiGateRequest) -> CiGateResult:
    """Fail a CI run on high-severity SAST findings (offline).

    `fail_on` sets the blocking threshold (critical|high|medium|low).
    Ignored rule ids are echoed back — a green gate never hides what
    was waived. Garbage entries are a 400, never silent. Sandbox
    returns a canned FAIL.
    """
    from services import sandbox as sandbox_mode
    from services.ci_gate import VALID_THRESHOLDS, evaluate, sandbox_result

    if str(req.fail_on or "").strip().lower() not in VALID_THRESHOLDS:
        raise HTTPException(
            status_code=400,
            detail=f"fail_on must be one of {', '.join(VALID_THRESHOLDS)}",
        )
    if sandbox_mode.enabled():
        return CiGateResult(**sandbox_result())
    try:
        result = evaluate(
            req.findings, fail_on=req.fail_on, ignore_rule_ids=req.ignore_rule_ids
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CiGateResult(**result)


@router.post("/sast/delta", response_model=SastDeltaResult)
def sast_delta(req: SastDeltaRequest) -> SastDeltaResult:
    """Diff-only SAST findings per PR (offline, read-only).

    `baseline` (main) vs `current` (the PR): exact (rule, file, line)
    matches are unchanged; same rule+file within `move_tolerance`
    lines is moved (code shifted, not a new vuln); the rest of current
    is new and the rest of baseline is fixed. Garbage entries are a
    400, never silent. Sandbox returns a canned diff. Nothing ledgers.
    """
    from services import sandbox as sandbox_mode
    from services.sast_delta import diff_findings, sandbox_result

    if sandbox_mode.enabled():
        return SastDeltaResult(**sandbox_result())
    try:
        result = diff_findings(
            req.baseline, req.current, move_tolerance=req.move_tolerance
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return SastDeltaResult(**result)


@router.post("/suppress/match", response_model=SuppressMatchResult)
def suppress_match(req: SuppressMatchRequest) -> SuppressMatchResult:
    """NOSAST with expiry + owner (offline, read-only).

    `bundle` (=== path === blocks) or `files` hold the sources;
    `findings` are matched against NOSAST directives on the finding's
    line or the line above. Expired waivers stop applying and are
    reported; malformed directives/entries are a 400, never silent.
    Sandbox returns a canned match. Nothing ledgers.
    """
    from services import sandbox as sandbox_mode
    from services.suppress import match_suppressions, parse_bundle, sandbox_result

    if sandbox_mode.enabled():
        return SuppressMatchResult(**sandbox_result())
    files = list(req.files or [])
    if req.bundle and req.bundle.strip():
        files.extend(parse_bundle(req.bundle))
    if not files:
        raise HTTPException(status_code=400, detail="bundle or files required")
    try:
        result = match_suppressions(files, req.findings)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return SuppressMatchResult(**result)


@router.post("/verify/fix", response_model=VerifyFixResult)
def verify_fix(req: VerifyFixRequest) -> VerifyFixResult:
    """Retest baseline against a rescan (offline, read-only).

    Exact (rule, file, line) matches persist; missing baseline
    findings are fixed; current-only findings are new unless an older
    snapshot in `history` had them — then they reappeared and are
    flagged flaky. Duplicate findings collapse to one, stated.
    Garbage entries are a 400, never silent. Sandbox returns a canned
    verification. Nothing ledgers.
    """
    from services import sandbox as sandbox_mode
    from services.verify_fix import sandbox_result, verify

    if sandbox_mode.enabled():
        return VerifyFixResult(**sandbox_result())
    try:
        result = verify(req.baseline, req.current, history=req.history)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return VerifyFixResult(**result)


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
