# Approval gate for sandbox / toolkit execution.
#
# The project's rule is "aggressive actions are opt-in"; this layer makes that
# rule executable instead of a convention. A policy can allow, deny or ask about
# a command before it runs, with rules by substring, regex or argv prefix. An
# "ask" creates a pending request; the caller retries with the approved request
# id. Every decision is recorded with who decided (human, rule or system) and a
# redacted argv so the audit log does not become a credential leak.
#
# Modes: enforce (default), audit (record but never block), off (bypass).
import hashlib
import json
import logging
import os
import re
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.approval")

ACTIONS = ("allow", "deny", "ask")
MATCH_TYPES = ("string", "regex", "argv_prefix")
MODES = ("enforce", "audit", "off")
SENSITIVE_FLAGS = {
    "-p",
    "-w",
    "--password",
    "--pass",
    "--passwd",
    "--token",
    "--api-key",
    "--secret",
    "-y",
}
MAX_DECISIONS = 5000

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    match_type  TEXT NOT NULL,
    pattern     TEXT NOT NULL,
    action      TEXT NOT NULL,
    priority    INTEGER NOT NULL DEFAULT 100,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS requests (
    id          TEXT PRIMARY KEY,
    fingerprint TEXT NOT NULL,
    tool        TEXT NOT NULL DEFAULT '',
    argv        TEXT NOT NULL,
    context     TEXT NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'pending',
    rule_id     TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    decided_at  TEXT,
    decided_by  TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS decisions (
    id          TEXT PRIMARY KEY,
    request_id  TEXT NOT NULL DEFAULT '',
    rule_id     TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    matched     TEXT NOT NULL DEFAULT '',
    decided_by  TEXT NOT NULL,
    tool        TEXT NOT NULL DEFAULT '',
    argv        TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status, created_at);
CREATE INDEX IF NOT EXISTS idx_requests_fp ON requests(fingerprint, status);
CREATE INDEX IF NOT EXISTS idx_decisions_time ON decisions(created_at);
"""


class ApprovalError(ValueError):
    pass


class ApprovalDenied(PermissionError):
    def __init__(self, decision: dict[str, Any]) -> None:
        super().__init__(decision.get("reason") or "approval denied")
        self.decision = decision


class ApprovalRequired(Exception):
    def __init__(self, decision: dict[str, Any]) -> None:
        super().__init__(decision.get("reason") or "approval required")
        self.decision = decision
        self.request_id = decision.get("request_id", "")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def mode() -> str:
    raw = os.environ.get("H4K_APPROVAL_MODE", "enforce").strip().lower()
    return raw if raw in MODES else "enforce"


def ttl_seconds() -> int:
    try:
        return max(30, int(os.environ.get("H4K_APPROVAL_TTL", "900")))
    except ValueError:
        return 900


def redact_argv(argv: list[str]) -> list[str]:
    """Hide values that follow common password/token flags before storing."""
    out: list[str] = []
    redact_next = False
    for token in argv:
        token = str(token)
        if redact_next:
            out.append("[REDACTED]")
            redact_next = False
            continue
        out.append(token)
        if token in SENSITIVE_FLAGS:
            redact_next = True
    return out


def fingerprint(argv: list[str]) -> str:
    material = json.dumps([str(a) for a in argv], separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:32]


class ApprovalStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else self.default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @staticmethod
    def default_path() -> Path:
        override = os.environ.get("H4K_APPROVAL_DB", "")
        if override:
            return Path(override)
        runtime = Path("/opt/h4k/data")
        if runtime.is_dir():
            return runtime / "approvals.db"
        return Path(__file__).resolve().parent.parent / "data" / "approvals.db"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    # -- rules --------------------------------------------------------------
    def rules(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        sql = "SELECT * FROM rules"
        if enabled_only:
            sql += " WHERE enabled=1"
        sql += " ORDER BY priority, created_at"
        with self._connect() as conn:
            rows = conn.execute(sql).fetchall()
        return [self._rule(r) for r in rows]

    def add_rule(
        self,
        name: str,
        pattern: str | list[str],
        *,
        action: str = "ask",
        match_type: str = "string",
        priority: int = 100,
        enabled: bool = True,
    ) -> dict[str, Any]:
        name = str(name or "").strip()
        if not name:
            raise ApprovalError("rule name is required")
        action = str(action or "").lower()
        if action not in ACTIONS:
            raise ApprovalError(f"action must be one of {', '.join(ACTIONS)}")
        if isinstance(pattern, list):
            match_type = "argv_prefix"
            pattern_text = json.dumps([str(p) for p in pattern])
        else:
            match_type = str(match_type or "string").lower()
            pattern_text = str(pattern or "")
            if not pattern_text.strip():
                raise ApprovalError("rule pattern is required")
            if match_type not in MATCH_TYPES:
                raise ApprovalError(
                    f"match_type must be one of {', '.join(MATCH_TYPES)}"
                )
            if match_type == "argv_prefix":
                try:
                    parsed = json.loads(pattern_text)
                except ValueError as exc:
                    raise ApprovalError(
                        "argv_prefix pattern must be a JSON array"
                    ) from exc
                if not isinstance(parsed, list) or not parsed:
                    raise ApprovalError(
                        "argv_prefix pattern must be a non-empty JSON array"
                    )
        rule_id = "A-" + uuid.uuid4().hex[:10]
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO rules (id, name, match_type, pattern, action, priority, "
                "enabled, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    rule_id,
                    name,
                    match_type,
                    pattern_text,
                    action,
                    int(priority),
                    1 if enabled else 0,
                    now,
                    now,
                ),
            )
            conn.commit()
        return self.get_rule(rule_id)  # type: ignore[return-value]

    def get_rule(self, rule_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
        return self._rule(row) if row else None

    def update_rule(self, rule_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        rule = self.get_rule(rule_id)
        if rule is None:
            raise KeyError("rule not found")
        data = {
            "name": rule["name"],
            "match_type": rule["match_type"],
            "pattern": rule["pattern"],
            "action": rule["action"],
            "priority": rule["priority"],
            "enabled": 1 if rule["enabled"] else 0,
        }
        for key in data:
            if key in (changes or {}):
                data[key] = changes[key]
        if data["action"] not in ACTIONS:
            raise ApprovalError(f"action must be one of {', '.join(ACTIONS)}")
        pattern = data["pattern"]
        if isinstance(pattern, list):
            data["match_type"] = "argv_prefix"
            data["pattern"] = json.dumps([str(p) for p in pattern])
        elif str(data["match_type"]) == "argv_prefix":
            try:
                parsed = json.loads(str(pattern))
            except ValueError as exc:
                raise ApprovalError("argv_prefix pattern must be a JSON array") from exc
            if not isinstance(parsed, list) or not parsed:
                raise ApprovalError(
                    "argv_prefix pattern must be a non-empty JSON array"
                )
        with self._connect() as conn:
            conn.execute(
                "UPDATE rules SET name=?, match_type=?, pattern=?, action=?, "
                "priority=?, enabled=?, updated_at=? WHERE id=?",
                (
                    str(data["name"]),
                    str(data["match_type"]),
                    str(data["pattern"]),
                    str(data["action"]),
                    int(data["priority"]),
                    1 if data["enabled"] else 0,
                    _now(),
                    rule_id,
                ),
            )
            conn.commit()
        return self.get_rule(rule_id)  # type: ignore[return-value]

    def delete_rule(self, rule_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM rules WHERE id=?", (rule_id,))
            conn.commit()
            return cursor.rowcount > 0

    @staticmethod
    def _rule(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["enabled"] = bool(data.get("enabled"))
        if data.get("match_type") == "argv_prefix":
            try:
                data["pattern"] = json.loads(data["pattern"])
            except ValueError:
                data["pattern"] = []
        return data

    # -- policy evaluation --------------------------------------------------
    def check(
        self,
        argv: list[str],
        *,
        tool: str = "",
        approval_id: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        argv = [str(a) for a in argv]
        if not argv:
            raise ApprovalError("argv is required")
        tool = tool or os.path.basename(argv[0])
        fp = fingerprint(argv)
        current_mode = mode()
        if current_mode == "off":
            return {
                "id": "",
                "action": "allow",
                "allowed": True,
                "decided_by": "system",
                "rule_id": "",
                "request_id": "",
                "fingerprint": fp,
                "tool": tool,
                "argv": redact_argv(argv),
                "reason": "approval gate off",
                "created_at": _now(),
            }
        self._expire()
        if approval_id:
            request = self.get_request(approval_id)
            if request and request["fingerprint"] == fp:
                if request["status"] == "approved":
                    return self._decision(
                        "allow",
                        "human",
                        tool,
                        argv,
                        fp,
                        request_id=approval_id,
                        reason=request.get("note") or "approved",
                    )
                if request["status"] == "denied":
                    decision = self._decision(
                        "deny",
                        "human",
                        tool,
                        argv,
                        fp,
                        request_id=approval_id,
                        reason=request.get("note") or "denied",
                    )
                    raise ApprovalDenied(decision)
            # unknown, mismatched or stale request: fall back to normal policy

        rule = self._match_rule(argv, tool)
        action = rule["action"] if rule else "allow"
        if current_mode == "audit":
            decision = self._decision(
                "allow",
                "rule" if rule else "system",
                tool,
                argv,
                fp,
                rule_id=rule["id"] if rule else "",
                matched=action,
                reason=(
                    f"audit: would {action} by rule {rule['name']}"
                    if rule
                    else "audit: no rule matched"
                ),
            )
            decision["matched_action"] = action
            return decision
        if action == "allow":
            return self._decision(
                "allow",
                "rule" if rule else "system",
                tool,
                argv,
                fp,
                rule_id=rule["id"] if rule else "",
                reason=rule["name"] if rule else "no rule matched",
            )
        if action == "deny":
            decision = self._decision(
                "deny",
                "rule",
                tool,
                argv,
                fp,
                rule_id=rule["id"] if rule else "",
                reason=f"denied by rule {rule['name']}" if rule else "denied",
            )
            raise ApprovalDenied(decision)
        # ask
        request = self._pending_for(fp)
        if request is None:
            request = self.create_request(argv, tool=tool, context=context)
        decision = self._decision(
            "ask",
            "rule",
            tool,
            argv,
            fp,
            rule_id=rule["id"] if rule else "",
            request_id=request["id"],
            reason=(
                f"approval required by rule {rule['name']}"
                if rule
                else "approval required"
            ),
        )
        decision["request"] = request
        raise ApprovalRequired(decision)

    def _match_rule(self, argv: list[str], tool: str) -> dict[str, Any] | None:
        command = " ".join(argv)
        tokens = [os.path.basename(argv[0]), *argv[1:]]
        for rule in self.rules(enabled_only=True):
            try:
                if rule["match_type"] == "string":
                    if str(rule["pattern"]).lower() in command.lower():
                        return rule
                elif rule["match_type"] == "regex":
                    if re.search(str(rule["pattern"]), command, re.IGNORECASE):
                        return rule
                elif rule["match_type"] == "argv_prefix":
                    pattern = (
                        rule["pattern"] if isinstance(rule["pattern"], list) else []
                    )
                    if pattern and tokens[: len(pattern)] == pattern:
                        return rule
            except re.error:
                logger.warning("invalid regex in approval rule %s", rule["id"])
        return None

    def _decision(
        self,
        action: str,
        decided_by: str,
        tool: str,
        argv: list[str],
        fp: str,
        *,
        rule_id: str = "",
        request_id: str = "",
        reason: str = "",
        matched: str = "",
    ) -> dict[str, Any]:
        now = _now()
        decision_id = "D-" + uuid.uuid4().hex[:10]
        redacted = redact_argv(argv)
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO decisions (id, request_id, rule_id, action, matched, "
                "decided_by, tool, argv, reason, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (
                    decision_id,
                    request_id,
                    rule_id,
                    action,
                    matched,
                    decided_by,
                    tool,
                    json.dumps(redacted),
                    reason,
                    now,
                ),
            )
            self._prune(conn)
            conn.commit()
        return {
            "id": decision_id,
            "action": action,
            "allowed": action == "allow",
            "decided_by": decided_by,
            "rule_id": rule_id,
            "request_id": request_id,
            "fingerprint": fp,
            "tool": tool,
            "argv": redacted,
            "reason": reason,
            "created_at": now,
        }

    def _prune(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            "DELETE FROM decisions WHERE id NOT IN "
            "(SELECT id FROM decisions ORDER BY created_at DESC LIMIT ?)",
            (MAX_DECISIONS,),
        )

    # -- approval requests --------------------------------------------------
    def create_request(
        self,
        argv: list[str],
        *,
        tool: str = "",
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        argv = [str(a) for a in argv]
        tool = tool or os.path.basename(argv[0])
        request_id = "Q-" + uuid.uuid4().hex[:12]
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO requests (id, fingerprint, tool, argv, context, status, "
                "created_at) VALUES (?,?,?,?,?,'pending',?)",
                (
                    request_id,
                    fingerprint(argv),
                    tool,
                    json.dumps(redact_argv(argv)),
                    json.dumps(context or {}, sort_keys=True, default=str)[:8000],
                    now,
                ),
            )
            conn.commit()
        return self.get_request(request_id)  # type: ignore[return-value]

    def _pending_for(self, fp: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM requests WHERE fingerprint=? AND status='pending' "
                "ORDER BY created_at DESC LIMIT 1",
                (fp,),
            ).fetchone()
        return self._request(row) if row else None

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM requests WHERE id=?", (request_id,)
            ).fetchone()
        return self._request(row) if row else None

    def requests(self, status: str = "", limit: int = 100) -> list[dict[str, Any]]:
        self._expire()
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM requests WHERE status=? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM requests ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [self._request(r) for r in rows]

    def approve(
        self, request_id: str, *, decided_by: str = "human", note: str = ""
    ) -> dict[str, Any]:
        return self._decide(request_id, "approved", "allow", decided_by, note)

    def deny(
        self, request_id: str, *, decided_by: str = "human", note: str = ""
    ) -> dict[str, Any]:
        return self._decide(request_id, "denied", "deny", decided_by, note)

    def _decide(
        self,
        request_id: str,
        status: str,
        action: str,
        decided_by: str,
        note: str,
    ) -> dict[str, Any]:
        request = self.get_request(request_id)
        if request is None:
            raise ApprovalError("approval request not found")
        if request["status"] != "pending":
            raise ApprovalError(f"request is already {request['status']}")
        now = _now()
        with self._connect() as conn:
            conn.execute(
                "UPDATE requests SET status=?, decided_at=?, decided_by=?, note=? "
                "WHERE id=?",
                (status, now, decided_by, note, request_id),
            )
            conn.commit()
        decision = self._decision(
            action,
            decided_by,
            request["tool"],
            request["argv"],
            request["fingerprint"],
            request_id=request_id,
            reason=note or status,
        )
        result = self.get_request(request_id) or request
        result["decision"] = decision
        return result

    def _expire(self) -> None:
        cutoff = (datetime.now(UTC) - timedelta(seconds=ttl_seconds())).isoformat(
            timespec="seconds"
        )
        with self._connect() as conn:
            conn.execute(
                "UPDATE requests SET status='expired', decided_at=?, decided_by='system' "
                "WHERE status='pending' AND created_at < ?",
                (_now(), cutoff),
            )
            conn.commit()

    @staticmethod
    def _request(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        data["argv"] = _loads(data.get("argv"), [])
        data["context"] = _loads(data.get("context"), {})
        return data

    # -- audit --------------------------------------------------------------
    def decisions(self, limit: int = 200) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM decisions ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["argv"] = _loads(item.get("argv"), [])
            out.append(item)
        return out

    def status(self) -> dict[str, Any]:
        self._expire()
        with self._connect() as conn:
            pending = conn.execute(
                "SELECT COUNT(*) FROM requests WHERE status='pending'"
            ).fetchone()[0]
        return {
            "mode": mode(),
            "ttl_seconds": ttl_seconds(),
            "rules": len(self.rules()),
            "pending": pending,
            "modes": list(MODES),
            "actions": list(ACTIONS),
            "match_types": list(MATCH_TYPES),
        }


def _loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(str(value))
    except (ValueError, TypeError):
        return default


def enforce(store: ApprovalStore | None = None, **kwargs: Any) -> dict[str, Any]:
    """Raise ApprovalDenied/ApprovalRequired when the policy blocks a command."""
    decision = (store or ApprovalStore()).check(kwargs.pop("argv", []), **kwargs)
    return decision
