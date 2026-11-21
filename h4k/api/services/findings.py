# Evidence-bound findings and retest verdicts.
#
# h4k already produced findings (scan/CVE, SAST, SCA, fuzz, AD, telemetry) and
# reports, but a finding was only as strong as the sentence next to it. This
# ledger makes the proof explicit: every finding can carry evidence artifacts
# (request/response, command output, file/note) with a content hash, and every
# retest records a verdict — reproduced, fixed or inconclusive — that cites the
# evidence it relied on.
#
# The model is deliberately small and local (SQLite), like the engagement and
# telemetry stores. It does not run tools itself; it is the audit trail the
# operator/report can point at. A retest without evidence is rejected, because
# "I checked it" is not a verdict.
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.findings")

SEVERITIES = ("critical", "high", "medium", "low", "info")
STATUSES = ("open", "in_progress", "fixed", "accepted", "false_positive")
VERDICTS = ("reproduced", "fixed", "inconclusive")
EVIDENCE_KINDS = (
    "request",
    "response",
    "http_exchange",
    "command",
    "output",
    "file",
    "note",
    "retest-output",
)
MAX_EVIDENCE_CHARS = 256 * 1024
MAX_LIST = 500

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT 'manual',
    host          TEXT NOT NULL DEFAULT '',
    port          INTEGER,
    service       TEXT NOT NULL DEFAULT '',
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'info',
    cwe           TEXT NOT NULL DEFAULT '',
    technique     TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'open',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_evidence (
    id          TEXT PRIMARY KEY,
    finding_id  TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'note',
    label       TEXT NOT NULL DEFAULT '',
    content     TEXT NOT NULL,
    sha256      TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}',
    captured_by TEXT NOT NULL DEFAULT 'operator',
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_retests (
    id           TEXT PRIMARY KEY,
    finding_id   TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    summary      TEXT NOT NULL,
    method       TEXT NOT NULL DEFAULT 'manual',
    tested_by    TEXT NOT NULL DEFAULT 'operator',
    evidence_ids TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_eng ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON finding_evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_retests_finding ON finding_retests(finding_id);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _text(value: Any, limit: int = 0) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, indent=2, sort_keys=True, default=str)
    else:
        text = str(value)
    return text[:limit] if limit else text


def _json(value: Any) -> str:
    try:
        return json.dumps(value or {}, sort_keys=True, default=str)[:40000]
    except (TypeError, ValueError):
        return "{}"


class FindingError(ValueError):
    """Validation error with an HTTP-friendly message."""


class FindingNotFound(KeyError):
    pass


class FindingStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else self.default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @staticmethod
    def default_path() -> Path:
        runtime = Path("/opt/h4k/data")
        if runtime.is_dir():
            return runtime / "findings.db"
        return Path(__file__).resolve().parent.parent / "data" / "findings.db"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    # -- findings -----------------------------------------------------------
    def create_finding(
        self,
        title: str,
        *,
        severity: str = "info",
        status: str = "open",
        source: str = "manual",
        engagement_id: str = "",
        host: str = "",
        port: int | None = None,
        service: str = "",
        cwe: str = "",
        technique: str = "",
        description: str = "",
    ) -> dict[str, Any]:
        title = _text(title, 300).strip()
        if not title:
            raise FindingError("title is required")
        severity = severity.lower()
        if severity not in SEVERITIES:
            raise FindingError(f"severity must be one of {', '.join(SEVERITIES)}")
        status = status.lower()
        if status not in STATUSES:
            raise FindingError(f"status must be one of {', '.join(STATUSES)}")
        finding_id = "F-" + uuid.uuid4().hex[:12]
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO findings (id, engagement_id, source, host, port, "
                "service, title, severity, cwe, technique, description, status, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    finding_id,
                    _text(engagement_id, 120),
                    _text(source, 80),
                    _text(host, 120),
                    int(port) if port not in (None, "") else None,
                    _text(service, 80),
                    title,
                    severity,
                    _text(cwe, 40),
                    _text(technique, 40),
                    _text(description, 20000),
                    status,
                    now,
                    now,
                ),
            )
            conn.commit()
        logger.info("finding created: %s (%s)", finding_id, title)
        return self.get_finding(finding_id)

    def list_findings(
        self,
        *,
        engagement_id: str = "",
        status: str = "",
        severity: str = "",
        q: str = "",
        limit: int = MAX_LIST,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if engagement_id:
            clauses.append("f.engagement_id = ?")
            params.append(engagement_id)
        if status:
            clauses.append("f.status = ?")
            params.append(status.lower())
        if severity:
            clauses.append("f.severity = ?")
            params.append(severity.lower())
        if q:
            clauses.append("(f.title LIKE ? OR f.host LIKE ? OR f.description LIKE ?)")
            like = f"%{q}%"
            params += [like, like, like]
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = max(1, min(int(limit), MAX_LIST))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT f.*, {self._counts_sql()} FROM findings f{where} "  # nosec B608 - fixed columns/where, bound values
                "ORDER BY f.updated_at DESC LIMIT ?",
                [*params, limit],
            ).fetchall()
        return [self._decorate(row) for row in rows]

    @staticmethod
    def _counts_sql() -> str:
        return (
            "(SELECT COUNT(*) FROM finding_evidence e WHERE e.finding_id=f.id) "
            "AS evidence_count, "
            "(SELECT COUNT(*) FROM finding_retests r WHERE r.finding_id=f.id) "
            "AS retest_count, "
            "(SELECT r.verdict FROM finding_retests r WHERE r.finding_id=f.id "
            "ORDER BY r.created_at DESC, r.rowid DESC LIMIT 1) AS last_verdict, "
            "(SELECT MAX(CASE WHEN r.verdict='reproduced' THEN 1 ELSE 0 END) "
            "FROM finding_retests r WHERE r.finding_id=f.id) AS ever_reproduced"
        )

    def get_finding(self, finding_id: str) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT f.*, {self._counts_sql()} FROM findings f WHERE f.id = ?",  # nosec B608 - fixed query, bound value
                (finding_id,),
            ).fetchone()
            if row is None:
                raise FindingNotFound(finding_id)
            evidence = conn.execute(
                "SELECT id, finding_id, kind, label, sha256, metadata, captured_by, "
                "created_at, length(content) AS chars FROM finding_evidence "
                "WHERE finding_id = ? ORDER BY created_at, rowid",
                (finding_id,),
            ).fetchall()
            retests = conn.execute(
                "SELECT * FROM finding_retests WHERE finding_id = ? "
                "ORDER BY created_at, rowid",
                (finding_id,),
            ).fetchall()
        finding = self._decorate(row)
        finding["evidence"] = [dict(item) for item in evidence]
        finding["retests"] = [
            {**dict(item), "evidence_ids": _loads(item["evidence_ids"], [])}
            for item in retests
        ]
        return finding

    def update_finding(
        self, finding_id: str, changes: dict[str, Any]
    ) -> dict[str, Any]:
        current = self.get_finding(finding_id)
        allowed = {
            "title",
            "severity",
            "status",
            "source",
            "host",
            "port",
            "service",
            "cwe",
            "technique",
            "description",
            "engagement_id",
        }
        updates: dict[str, Any] = {}
        for key, value in (changes or {}).items():
            if key not in allowed:
                continue
            if key == "severity":
                value = str(value).lower()
                if value not in SEVERITIES:
                    raise FindingError(
                        f"severity must be one of {', '.join(SEVERITIES)}"
                    )
            if key == "status":
                value = str(value).lower()
                if value not in STATUSES:
                    raise FindingError(f"status must be one of {', '.join(STATUSES)}")
            if key == "title" and not str(value).strip():
                raise FindingError("title cannot be empty")
            if key == "port" and value in (None, ""):
                value = None
            updates[key] = value
        if not updates:
            return current
        updates["updated_at"] = _now()
        assignments = ", ".join(f"{name} = ?" for name in updates)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE findings SET {assignments} WHERE id = ?",  # nosec B608 - fixed column names, bound values
                [*updates.values(), finding_id],
            )
            conn.commit()
        return self.get_finding(finding_id)

    def delete_finding(self, finding_id: str) -> bool:
        with self._connect() as conn:
            conn.execute(
                "DELETE FROM finding_evidence WHERE finding_id = ?", (finding_id,)
            )
            conn.execute(
                "DELETE FROM finding_retests WHERE finding_id = ?", (finding_id,)
            )
            cursor = conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
            conn.commit()
        return cursor.rowcount > 0

    # -- evidence -----------------------------------------------------------
    def add_evidence(
        self,
        finding_id: str,
        *,
        content: Any,
        kind: str = "note",
        label: str = "",
        metadata: dict[str, Any] | None = None,
        captured_by: str = "operator",
    ) -> dict[str, Any]:
        self.get_finding(finding_id)  # 404 before writing
        kind = kind or "note"
        if kind not in EVIDENCE_KINDS:
            raise FindingError(
                f"evidence kind must be one of {', '.join(EVIDENCE_KINDS)}"
            )
        text = _text(content, MAX_EVIDENCE_CHARS).strip()
        if not text:
            raise FindingError("evidence content is required")
        evidence_id = "E-" + uuid.uuid4().hex[:12]
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO finding_evidence (id, finding_id, kind, label, content, "
                "sha256, metadata, captured_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    evidence_id,
                    finding_id,
                    kind,
                    _text(label, 200),
                    text,
                    digest,
                    _json(metadata),
                    _text(captured_by, 80) or "operator",
                    now,
                ),
            )
            conn.execute(
                "UPDATE findings SET updated_at = ? WHERE id = ?", (now, finding_id)
            )
            conn.commit()
        return {
            "id": evidence_id,
            "finding_id": finding_id,
            "kind": kind,
            "label": _text(label, 200),
            "sha256": digest,
            "chars": len(text),
            "captured_by": captured_by,
            "created_at": now,
        }

    def evidence(self, finding_id: str) -> list[dict[str, Any]]:
        self.get_finding(finding_id)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, finding_id, kind, label, content, sha256, metadata, "
                "captured_by, created_at FROM finding_evidence WHERE finding_id = ? "
                "ORDER BY created_at, rowid",
                (finding_id,),
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["metadata"] = _loads(item.get("metadata"), {})
            out.append(item)
        return out

    # -- retests ------------------------------------------------------------
    def record_retest(
        self,
        finding_id: str,
        *,
        verdict: str,
        summary: str,
        evidence_ids: list[str] | None = None,
        inline_evidence: Any = None,
        method: str = "manual",
        tested_by: str = "operator",
    ) -> dict[str, Any]:
        finding = self.get_finding(finding_id)
        verdict = str(verdict or "").lower()
        if verdict not in VERDICTS:
            raise FindingError(f"verdict must be one of {', '.join(VERDICTS)}")
        summary = _text(summary, 4000).strip()
        if not summary:
            raise FindingError("retest summary is required")
        cited = [str(e) for e in (evidence_ids or []) if e]
        if inline_evidence:
            added = self.add_evidence(
                finding_id,
                content=inline_evidence,
                kind="retest-output",
                label=f"retest: {verdict}",
                captured_by=tested_by,
            )
            cited.append(added["id"])
        cited = list(dict.fromkeys(cited))
        owned = {item["id"] for item in self.evidence(finding_id)}
        missing = [e for e in cited if e not in owned]
        if missing:
            raise FindingError(f"evidence does not belong to this finding: {missing}")
        if not cited:
            raise FindingError(
                "a retest must cite at least one evidence item "
                "(attach evidence first, or pass inline_evidence)"
            )
        retest_id = "R-" + uuid.uuid4().hex[:12]
        now = _now()
        new_status = str(finding["status"])
        if verdict == "fixed":
            new_status = "fixed"
        elif verdict == "reproduced":
            new_status = "open"
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO finding_retests (id, finding_id, verdict, summary, "
                "method, tested_by, evidence_ids, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    retest_id,
                    finding_id,
                    verdict,
                    summary,
                    _text(method, 80) or "manual",
                    _text(tested_by, 80) or "operator",
                    json.dumps(cited),
                    now,
                ),
            )
            conn.execute(
                "UPDATE findings SET status = ?, updated_at = ? WHERE id = ?",
                (new_status, now, finding_id),
            )
            conn.commit()
        logger.info("finding retest: %s -> %s (%s)", finding_id, verdict, retest_id)
        return {
            "id": retest_id,
            "finding_id": finding_id,
            "verdict": verdict,
            "summary": summary,
            "evidence_ids": cited,
            "method": method,
            "tested_by": tested_by,
            "created_at": now,
            "finding_status": new_status,
            "verified": verdict == "reproduced" or bool(finding.get("verified")),
        }

    def retests(self, finding_id: str) -> list[dict[str, Any]]:
        self.get_finding(finding_id)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM finding_retests WHERE finding_id = ? "
                "ORDER BY created_at, rowid",
                (finding_id,),
            ).fetchall()
        return [
            {**dict(row), "evidence_ids": _loads(row["evidence_ids"], [])}
            for row in rows
        ]

    # -- reporting ----------------------------------------------------------
    def summary(self, engagement_id: str = "") -> dict[str, Any]:
        findings = self.list_findings(engagement_id=engagement_id, limit=MAX_LIST)
        by_status: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for finding in findings:
            by_status[finding["status"]] = by_status.get(finding["status"], 0) + 1
            by_severity[finding["severity"]] = (
                by_severity.get(finding["severity"], 0) + 1
            )
        return {
            "findings": len(findings),
            "verified": sum(1 for f in findings if f["verified"]),
            "evidence_backed": sum(1 for f in findings if f["evidence_backed"]),
            "fixed": sum(1 for f in findings if f["status"] == "fixed"),
            "by_status": by_status,
            "by_severity": by_severity,
            "evidence": sum(int(f["evidence_count"]) for f in findings),
            "retests": sum(int(f["retest_count"]) for f in findings),
        }

    def report_section(self, engagement_id: str = "") -> str:
        findings = self.list_findings(engagement_id=engagement_id, limit=MAX_LIST)
        if not findings:
            return "## Finding ledger\n\nNo evidence-backed findings recorded.\n"
        lines = [
            "## Finding ledger",
            "",
            "| Severity | Finding | Status | Evidence | Last retest |",
            "|---|---|---|---|---|",
        ]
        for finding in findings:
            lines.append(
                "| {severity} | `{fid}` {title} | {status}{verified} | {evidence} | "
                "{retest} |".format(
                    severity=finding["severity"].upper(),
                    fid=finding["id"],
                    title=_md(str(finding["title"])),
                    status=finding["status"],
                    verified=" · verified" if finding["verified"] else "",
                    evidence=finding["evidence_count"],
                    retest=finding.get("last_verdict") or "—",
                )
            )
        lines.append("")
        for finding in findings[:100]:
            detail = self.get_finding(finding["id"])
            lines.append(f"### {finding['id']} — {_md(str(finding['title']))}")
            target = str(finding.get("host") or "")
            if target and finding.get("port"):
                target += f":{finding['port']}"
            lines.append(
                f"- **{finding['severity']}** · {finding['status']} · "
                f"source `{finding.get('source') or 'manual'}`"
                + (f" · target `{_md(target)}`" if target else "")
            )
            if finding.get("technique"):
                lines.append(f"- ATT&CK: `{finding['technique']}`")
            if finding.get("cwe"):
                lines.append(f"- CWE: `{finding['cwe']}`")
            if finding.get("description"):
                lines.append(f"- {_md(str(finding['description']))}")
            for item in detail["evidence"][:10]:
                lines.append(
                    f"- evidence `{item['kind']}` {_md(str(item.get('label') or ''))} "
                    f"(sha256 `{str(item['sha256'])[:16]}…`)"
                )
            for item in detail["retests"][:10]:
                lines.append(
                    f"- retest **{item['verdict']}** — {_md(str(item['summary']))} "
                    f"(evidence: {len(item['evidence_ids'])})"
                )
            lines.append("")
        summary = self.summary(engagement_id)
        lines.append(
            f"> Ledger totals: {summary['findings']} findings, "
            f"{summary['verified']} verified, {summary['evidence']} evidence items, "
            f"{summary['retests']} retests."
        )
        lines.append("")
        return "\n".join(lines)

    def report_markdown(self, engagement_id: str = "") -> str:
        return (
            "# Evidence-backed finding ledger\n\n"
            + self.report_section(engagement_id)
            + "\n> Generated by h4k. A finding without cited evidence is a lead, "
            "not proof.\n"
        )

    @staticmethod
    def _decorate(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["evidence_backed"] = int(data.get("evidence_count") or 0) > 0
        data["verified"] = bool(data.get("ever_reproduced"))
        data.pop("ever_reproduced", None)
        return data


def _loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(str(value))
    except (ValueError, TypeError):
        return default


def _md(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")[:500]
