# Evidence-bound finding ledger endpoints.
#
# A finding is a claim; evidence is the proof; a retest is the verdict. These
# routes let the UI/API attach request/response/command evidence and record a
# reproduced/fixed/inconclusive retest that cites it. Reads are viewer-level,
# writes are operator-level (the default role rule for POST/PATCH/DELETE).
import ipaddress
import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from services.findings import FindingError, FindingNotFound, FindingStore

logger = logging.getLogger("h4k.routers.findings")

router = APIRouter(prefix="/api/findings")

_store: FindingStore | None = None


def get_store() -> FindingStore:
    global _store
    if _store is None:
        _store = FindingStore()
    return _store


def reset_store() -> None:
    global _store
    _store = None


def _check_scope(engagement_id: str, host: str) -> None:
    """When an engagement is supplied, its CIDRs still constrain findings."""
    if not engagement_id:
        return
    try:
        from services.engagement import EngagementStore

        store = EngagementStore()
        engagements = store.list_engagements()
    except Exception:  # pragma: no cover - partial test environments
        return
    if not any(e["id"] == engagement_id for e in engagements):
        raise HTTPException(status_code=404, detail="engagement not found")
    if not host:
        return
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return  # hostname: scope is enforced on the resolved IP at scan time
    if not store.in_scope(engagement_id, host):
        raise HTTPException(
            status_code=403,
            detail=f"{host} is outside the engagement's authorized scope",
        )


def _body(body: dict[str, Any] | None) -> dict[str, Any]:
    return body or {}


@router.get("")
def list_findings(
    engagement_id: str = "",
    status: str = "",
    severity: str = "",
    q: str = "",
    limit: int = 200,
) -> dict[str, Any]:
    store = get_store()
    findings = store.list_findings(
        engagement_id=engagement_id,
        status=status,
        severity=severity,
        q=q,
        limit=limit,
    )
    return {
        "findings": findings,
        "count": len(findings),
        "summary": store.summary(engagement_id),
    }


@router.post("")
def create_finding(body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = _body(body)
    engagement_id = str(data.get("engagement_id") or "")
    _check_scope(engagement_id, str(data.get("host") or ""))
    try:
        return get_store().create_finding(
            str(data.get("title") or ""),
            severity=str(data.get("severity") or "info"),
            status=str(data.get("status") or "open"),
            source=str(data.get("source") or "manual"),
            engagement_id=engagement_id,
            host=str(data.get("host") or ""),
            port=data.get("port"),
            service=str(data.get("service") or ""),
            cwe=str(data.get("cwe") or ""),
            technique=str(data.get("technique") or ""),
            description=str(data.get("description") or ""),
        )
    except FindingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid port: {exc}") from exc


@router.get("/summary")
def findings_summary(engagement_id: str = "") -> dict[str, Any]:
    return get_store().summary(engagement_id)


@router.get("/report")
def findings_report(engagement_id: str = "", fmt: str = "md") -> dict[str, Any]:
    store = get_store()
    if fmt.lower() == "json":
        return {
            "fmt": "json",
            "summary": store.summary(engagement_id),
            "findings": store.list_findings(engagement_id=engagement_id, limit=500),
        }
    return {
        "fmt": "md",
        "content": store.report_markdown(engagement_id),
    }


@router.get("/{finding_id}")
def get_finding(finding_id: str) -> dict[str, Any]:
    try:
        return get_store().get_finding(finding_id)
    except FindingNotFound as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc


@router.patch("/{finding_id}")
def update_finding(
    finding_id: str, body: dict[str, Any] | None = None
) -> dict[str, Any]:
    try:
        return get_store().update_finding(finding_id, _body(body))
    except FindingNotFound as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except FindingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{finding_id}")
def delete_finding(finding_id: str) -> dict[str, Any]:
    if not get_store().delete_finding(finding_id):
        raise HTTPException(status_code=404, detail="finding not found")
    return {"status": "deleted", "id": finding_id}


@router.post("/{finding_id}/evidence")
def add_evidence(finding_id: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    data = _body(body)
    metadata = data.get("metadata") or {}
    if not isinstance(metadata, dict):
        raise HTTPException(status_code=400, detail="metadata must be an object")
    try:
        return get_store().add_evidence(
            finding_id,
            content=data.get("content"),
            kind=str(data.get("kind") or "note"),
            label=str(data.get("label") or ""),
            metadata=metadata,
            captured_by=str(data.get("captured_by") or "operator"),
        )
    except FindingNotFound as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except FindingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{finding_id}/evidence")
def list_evidence(finding_id: str) -> dict[str, Any]:
    try:
        evidence = get_store().evidence(finding_id)
    except FindingNotFound as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    return {"evidence": evidence, "count": len(evidence)}


@router.post("/{finding_id}/retest")
def record_retest(
    finding_id: str, body: dict[str, Any] | None = None
) -> dict[str, Any]:
    data = _body(body)
    evidence_ids = data.get("evidence_ids") or []
    if not isinstance(evidence_ids, list):
        raise HTTPException(status_code=400, detail="evidence_ids must be a list")
    try:
        return get_store().record_retest(
            finding_id,
            verdict=str(data.get("verdict") or ""),
            summary=str(data.get("summary") or ""),
            evidence_ids=[str(e) for e in evidence_ids],
            inline_evidence=data.get("inline_evidence"),
            method=str(data.get("method") or "manual"),
            tested_by=str(data.get("tested_by") or "operator"),
        )
    except FindingNotFound as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    except FindingError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{finding_id}/retests")
def list_retests(finding_id: str) -> dict[str, Any]:
    try:
        retests = get_store().retests(finding_id)
    except FindingNotFound as exc:
        raise HTTPException(status_code=404, detail="finding not found") from exc
    return {"retests": retests, "count": len(retests)}
