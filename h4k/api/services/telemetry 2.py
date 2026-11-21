# Endpoint telemetry (#94): ingest, normalize, correlate and score host events.
#
# The point is not to be a SIEM. It is to close the loop between what h4k does
# and what a defender would see: accept sysmon/auditd/osquery/zeek-shaped
# events, normalize the half-dozen fields that matter, apply a small set of
# Sigma-style rules, and return detections with ATT&CK technique IDs. An
# operator can then show "this action produced these events and these alerts"
# without standing up Elastic.
#
# The store is SQLite, idempotent on event_uid, and bounded by the caller's
# query limit. No event is ever re-emitted to an external system.
import contextlib
import hashlib
import json
import logging
import re
import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

logger = logging.getLogger("h4k.telemetry")

MAX_BATCH = 1000
DEFAULT_LIMIT = 200
MAX_LIMIT = 2000

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_uid   TEXT PRIMARY KEY,
    ts          TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    host        TEXT NOT NULL DEFAULT '',
    event_id    TEXT NOT NULL DEFAULT '',
    channel     TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT 'info',
    technique   TEXT NOT NULL DEFAULT '',
    message     TEXT NOT NULL DEFAULT '',
    data        TEXT NOT NULL DEFAULT '{}',
    ingested_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS detections (
    event_uid   TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    technique   TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    host        TEXT NOT NULL DEFAULT '',
    matched_at  TEXT NOT NULL,
    PRIMARY KEY (event_uid, rule_id)
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_det_time ON detections(matched_at);
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _norm_ts(value: Any) -> str:
    if value is None or value == "":
        return _now_iso()
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10**12:
            number /= 1000.0
        try:
            return datetime.fromtimestamp(number, UTC).isoformat(timespec="seconds")
        except (OverflowError, OSError, ValueError):
            return _now_iso()
    text = str(value).strip()
    if text.isdigit():
        return _norm_ts(int(text))
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).isoformat(timespec="seconds")


def _first(source: Mapping[str, Any], *names: str, default: Any = "") -> Any:
    for name in names:
        value = source.get(name)
        if value not in (None, ""):
            return value
    return default


def _event_uid(raw: dict[str, Any], normalized: dict[str, Any]) -> str:
    explicit = _first(raw, "event_uid", "uid")
    if explicit:
        return str(explicit)[:200]
    material = "|".join(
        str(normalized.get(key, ""))
        for key in ("ts", "source", "host", "event_id", "message")
    )
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:40]


def normalize(raw: dict[str, Any], *, default_source: str = "manual") -> dict[str, Any]:
    """Map a sysmon/auditd/osquery/zeek-ish event onto the canonical fields."""
    if not isinstance(raw, dict):
        raw = {"message": str(raw)}
    process = (
        cast(dict[str, Any], raw.get("process"))
        if isinstance(raw.get("process"), dict)
        else {}
    )
    event = (
        cast(dict[str, Any], raw.get("event"))
        if isinstance(raw.get("event"), dict)
        else {}
    )
    agent = (
        cast(dict[str, Any], raw.get("agent"))
        if isinstance(raw.get("agent"), dict)
        else {}
    )
    ts = _first(raw, "ts", "timestamp", "@timestamp", "TimeCreated", "time", "utc_time")
    host = _first(raw, "host", "Computer", "hostname", "computer", "agent_name")
    if not host:
        host = _first(agent, "hostname", "name")
    source = _first(raw, "source", "channel", "provider", "log_source")
    if not source:
        source = _first(event, "source", "dataset", default=default_source)
    event_id = _first(raw, "event_id", "EventID", "eventid", "code")
    if not event_id:
        event_id = _first(event, "id", "code")
    channel = _first(raw, "channel", "Channel", "log_name")
    message = _first(raw, "message", "Message", "msg", "command_line", "description")
    if not message:
        message = _first(process, "command_line", "name")
    severity = str(_first(raw, "severity", "level", default="info")).lower()
    technique = str(_first(raw, "technique", "technique_id", "attack", default=""))
    normalized = {
        "ts": _norm_ts(ts),
        "source": str(source)[:80],
        "host": str(host)[:120],
        "event_id": str(event_id)[:40],
        "channel": str(channel)[:120],
        "severity": (
            severity
            if severity in {"info", "low", "medium", "high", "critical"}
            else "info"
        ),
        "technique": technique[:40],
        "message": str(message)[:8000],
        "data": raw,
    }
    normalized["event_uid"] = _event_uid(raw, normalized)
    return normalized


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------
def _has(text: str, *needles: str) -> bool:
    lowered = text.lower()
    return all(n.lower() in lowered for n in needles)


def _any(text: str, *needles: str) -> bool:
    lowered = text.lower()
    return any(n.lower() in lowered for n in needles)


_RULES: list[dict[str, Any]] = [
    {
        "id": "PS-ENCODED",
        "title": "Encoded PowerShell command",
        "severity": "high",
        "technique": "T1059.001",
        "description": "PowerShell was invoked with an encoded command (-enc/-EncodedCommand).",
        "match": lambda e: _has(e["message"], "powershell")
        and _any(e["message"], "-enc", "-encodedcommand", "frombase64string"),
    },
    {
        "id": "LSASS-ACCESS",
        "title": "Possible credential dumping from LSASS",
        "severity": "critical",
        "technique": "T1003.001",
        "description": "A process references lsass memory dump activity.",
        "match": lambda e: _has(e["message"], "lsass")
        and _any(
            e["message"],
            "dump",
            "procdump",
            "mimikatz",
            "comsvcs",
            "minidump",
            "sekurlsa",
        ),
    },
    {
        "id": "KERBEROAST",
        "title": "Kerberoasting-shaped TGS request",
        "severity": "high",
        "technique": "T1558.003",
        "description": "A 4769 ticket request used RC4 (0x17), the classic roast signature.",
        "match": lambda e: (
            e["event_id"] == "4769"
            and _any(e["message"], "0x17", "rc4", "etype 23", "encryption type 23")
        ),
    },
    {
        "id": "ASREP-ROAST",
        "title": "AS-REP roast-shaped TGT request",
        "severity": "high",
        "technique": "T1558.004",
        "description": "A 4768 ticket was issued without Kerberos pre-authentication.",
        "match": lambda e: e["event_id"] == "4768"
        and _any(e["message"], "preauth", "pre-auth", "0x0", "no preauthentication"),
    },
    {
        "id": "LOG-CLEARED",
        "title": "Security log cleared",
        "severity": "critical",
        "technique": "T1070.001",
        "description": "Event 1102 or auditd log rotation by a user indicates log tampering.",
        "match": lambda e: e["event_id"] == "1102"
        or _has(e["message"], "audit", "cleared")
        or _has(e["message"], "log", "cleared"),
    },
    {
        "id": "SERVICE-CREATED",
        "title": "New service installed",
        "severity": "high",
        "technique": "T1543.003",
        "description": "A service was created (7045); persistence or lateral tooling.",
        "match": lambda e: e["event_id"] == "7045"
        or _has(e["message"], "new service", "service installed"),
    },
    {
        "id": "SCHEDULED-TASK",
        "title": "Scheduled task created",
        "severity": "medium",
        "technique": "T1053.005",
        "description": "A scheduled task was registered (4698 / TaskScheduler 106).",
        "match": lambda e: e["event_id"] in {"4698", "106"}
        or (
            _any(e["message"], "scheduled task", "schtasks")
            and _any(e["message"], "create", "register")
        ),
    },
    {
        "id": "NEW-USER",
        "title": "New local/domain account created",
        "severity": "medium",
        "technique": "T1136.001",
        "description": "Account creation (4720/4722) can be legitimate or persistence.",
        "match": lambda e: e["event_id"] in {"4720", "4722", "4724"}
        or _any(e["message"], "useradd", "new user"),
    },
    {
        "id": "GROUP-CHANGE",
        "title": "Privileged group membership changed",
        "severity": "high",
        "technique": "T1098",
        "description": "A member was added to a security group (4728/4732/4756).",
        "match": lambda e: e["event_id"] in {"4728", "4732", "4756"}
        or _has(e["message"], "added to group"),
    },
    {
        "id": "SMB-LATERAL",
        "title": "SMB share access / lateral movement",
        "severity": "medium",
        "technique": "T1021.002",
        "description": "A network share was accessed (5140/5145); verify the source.",
        "match": lambda e: e["event_id"] in {"5140", "5145"}
        or (
            _has(e["message"], "smb", "share")
            and _any(e["message"], "access", "connect")
        ),
    },
    {
        "id": "PROCESS-INJECTION",
        "title": "Process injection API sequence",
        "severity": "high",
        "technique": "T1055",
        "description": "CreateRemoteThread / QueueUserAPC / WriteProcessMemory observed.",
        "match": lambda e: _any(
            e["message"],
            "createremotethread",
            "queueuserapc",
            "writeprocessmemory",
            "setthreadcontext",
        ),
    },
    {
        "id": "DEFENDER-DISABLED",
        "title": "Defender / audit policy tampering",
        "severity": "high",
        "technique": "T1562.001",
        "description": "Security controls were disabled via command line.",
        "match": lambda e: _any(
            e["message"],
            "set-mppreference",
            "disableantispyware",
            "disablebehaviormonitoring",
            "stop defender",
        ),
    },
    {
        "id": "DNS-TUNNEL",
        "title": "Long, high-entropy DNS query",
        "severity": "medium",
        "technique": "T1048.003",
        "description": "A DNS query label is unusually long and base64-like.",
        "match": lambda e: (
            e["source"].lower() in {"dns", "zeek", "sysmon"}
            or "dns" in e["channel"].lower()
        )
        and bool(re.search(r"[A-Za-z0-9+/]{50,}={0,2}", e["message"])),
    },
    {
        "id": "MODBUS-WRITE",
        "title": "Modbus write function code",
        "severity": "critical",
        "technique": "T0855",
        "description": "A Modbus write (FC5/6/15/16) was observed; OT state changed.",
        "match": lambda e: _has(e["message"], "modbus")
        and _any(
            e["message"], "fc=5", "fc=6", "fc=15", "fc=16", "function 5", "function 6"
        ),
    },
    {
        "id": "MQTT-BRUTE",
        "title": "Repeated MQTT CONNECT failures",
        "severity": "medium",
        "technique": "T1110.001",
        "description": "Multiple rejected MQTT connections suggest credential guessing.",
        "match": lambda e: _has(e["message"], "mqtt")
        and _any(
            e["message"], "connack", "rejected", "return_code=5", "not authorized"
        ),
    },
]


def rules() -> list[dict[str, Any]]:
    return [
        {
            "id": rule["id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "technique": rule["technique"],
            "description": rule["description"],
        }
        for rule in _RULES
    ]


def _match_rules(event: dict[str, Any]) -> list[dict[str, Any]]:
    hits = []
    for rule in _RULES:
        try:
            if rule["match"](event):
                hits.append(rule)
        except Exception:  # pragma: no cover - a broken rule must not drop events
            logger.warning("telemetry rule %s raised", rule["id"])
    return hits


class TelemetryStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else self.default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @staticmethod
    def default_path() -> Path:
        runtime = Path("/opt/h4k/data")
        if runtime.is_dir():
            return runtime / "telemetry.db"
        return Path(__file__).resolve().parent.parent / "data" / "telemetry.db"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    # -- write --------------------------------------------------------------
    def ingest(
        self, events: list[dict[str, Any]], *, source: str = "manual"
    ) -> dict[str, Any]:
        batch = events[:MAX_BATCH]
        accepted = 0
        duplicates = 0
        detections: list[dict[str, Any]] = []
        now = _now_iso()
        with self._connect() as conn:
            for raw in batch:
                event = normalize(raw, default_source=source)
                try:
                    conn.execute(
                        "INSERT INTO events (event_uid, ts, source, host, event_id, "
                        "channel, severity, technique, message, data, ingested_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            event["event_uid"],
                            event["ts"],
                            event["source"],
                            event["host"],
                            event["event_id"],
                            event["channel"],
                            event["severity"],
                            event["technique"],
                            event["message"],
                            json.dumps(event["data"], default=str)[:40000],
                            now,
                        ),
                    )
                    accepted += 1
                except sqlite3.IntegrityError:
                    duplicates += 1
                    continue
                for rule in _match_rules(event):
                    detection = {
                        "event_uid": event["event_uid"],
                        "rule_id": rule["id"],
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "technique": rule["technique"],
                        "description": rule["description"],
                        "host": event["host"],
                        "matched_at": event["ts"],
                    }
                    conn.execute(
                        "INSERT OR IGNORE INTO detections (event_uid, rule_id, title, "
                        "severity, technique, description, host, matched_at) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            detection["event_uid"],
                            detection["rule_id"],
                            detection["title"],
                            detection["severity"],
                            detection["technique"],
                            detection["description"],
                            detection["host"],
                            detection["matched_at"],
                        ),
                    )
                    detections.append(detection)
            detections.extend(self._aggregate(conn))
            conn.commit()
        return {
            "accepted": accepted,
            "duplicates": duplicates,
            "detections": detections,
            "detection_count": len(detections),
            "batch_size": len(batch),
        }

    def _aggregate(self, conn: sqlite3.Connection) -> list[dict[str, Any]]:
        """Burst rules that need more than one event (failed logons)."""
        since = (datetime.now(UTC) - timedelta(minutes=5)).isoformat(timespec="seconds")
        rows = conn.execute(
            "SELECT host, COUNT(*) AS n FROM events "
            "WHERE event_id='4625' AND ts >= ? GROUP BY host HAVING n >= 10",
            (since,),
        ).fetchall()
        out = []
        for row in rows:
            uid = f"agg-4625-{row['host']}-{since[:16]}"
            detection = {
                "event_uid": uid,
                "rule_id": "FAILED-LOGON-BURST",
                "title": "Failed-logon burst",
                "severity": "high",
                "technique": "T1110.003",
                "description": (
                    f"{row['n']} failed logons on {row['host']} in five minutes; "
                    "possible password spray."
                ),
                "host": row["host"],
                "matched_at": _now_iso(),
            }
            conn.execute(
                "INSERT OR IGNORE INTO detections (event_uid, rule_id, title, "
                "severity, technique, description, host, matched_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                tuple(
                    detection[key]
                    for key in (
                        "event_uid",
                        "rule_id",
                        "title",
                        "severity",
                        "technique",
                        "description",
                        "host",
                        "matched_at",
                    )
                ),
            )
            out.append(detection)
        return out

    # -- read ---------------------------------------------------------------
    def events(
        self,
        *,
        limit: int = DEFAULT_LIMIT,
        host: str = "",
        source: str = "",
        technique: str = "",
        severity: str = "",
        q: str = "",
        since: str = "",
    ) -> list[dict[str, Any]]:
        clauses, params = [], []
        for column, value in (
            ("host", host),
            ("source", source),
            ("technique", technique),
            ("severity", severity),
        ):
            if value:
                clauses.append(f"{column} = ?")
                params.append(value)
        if q:
            clauses.append("(message LIKE ? OR event_id LIKE ? OR channel LIKE ?)")
            like = f"%{q}%"
            params += [like, like, like]
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        limit = max(1, min(int(limit), MAX_LIMIT))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM events{where} ORDER BY ts DESC LIMIT ?",  # nosec B608 - fixed columns, bound values
                [*params, limit],
            ).fetchall()
        return [self._row(r) for r in rows]

    def detections(self, *, limit: int = DEFAULT_LIMIT) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), MAX_LIMIT))
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM detections ORDER BY matched_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            det_total = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
            by_source = {
                row["source"] or "unknown": row["n"]
                for row in conn.execute(
                    "SELECT source, COUNT(*) AS n FROM events GROUP BY source"
                )
            }
            by_severity = {
                row["severity"] or "info": row["n"]
                for row in conn.execute(
                    "SELECT severity, COUNT(*) AS n FROM detections GROUP BY severity"
                )
            }
            top_rules = [
                {"rule_id": row["rule_id"], "title": row["title"], "count": row["n"]}
                for row in conn.execute(
                    "SELECT rule_id, title, COUNT(*) AS n FROM detections "
                    "GROUP BY rule_id, title ORDER BY n DESC LIMIT 10"
                )
            ]
            techniques = [
                {"technique": row["technique"], "count": row["n"]}
                for row in conn.execute(
                    "SELECT technique, COUNT(*) AS n FROM detections "
                    "WHERE technique != '' GROUP BY technique ORDER BY n DESC"
                )
            ]
            earliest = conn.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
        return {
            "events": total,
            "detections": det_total,
            "by_source": by_source,
            "detections_by_severity": by_severity,
            "top_rules": top_rules,
            "techniques": techniques,
            "first_event": earliest[0],
            "last_event": earliest[1],
            "rules": len(_RULES),
        }

    def reset(self) -> dict[str, Any]:
        with self._connect() as conn:
            conn.execute("DELETE FROM detections")
            conn.execute("DELETE FROM events")
            conn.commit()
        return {"status": "reset"}

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        data = dict(row)
        with contextlib.suppress(ValueError, TypeError):
            data["data"] = json.loads(data.get("data") or "{}")
        return data


def simulate_demo() -> dict[str, Any]:
    """Canned attack-shaped telemetry for demos and tests (no h4k action needed)."""
    now = datetime.now(UTC).isoformat(timespec="seconds")
    return {
        "source": "demo",
        "events": [
            {
                "ts": now,
                "host": "dc01.lab.local",
                "source": "sysmon",
                "event_id": "1",
                "message": "powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA",
            },
            {
                "ts": now,
                "host": "dc01.lab.local",
                "source": "security",
                "event_id": "4769",
                "message": "Kerberos service ticket requested, encryption type 0x17 (RC4)",
            },
            {
                "ts": now,
                "host": "dc01.lab.local",
                "source": "security",
                "event_id": "4768",
                "message": "TGT requested with preauth disabled (0x0)",
            },
            {
                "ts": now,
                "host": "fileserver.lab.local",
                "source": "sysmon",
                "event_id": "10",
                "message": "procdump.exe accessed lsass.exe memory",
            },
            {
                "ts": now,
                "host": "plc01.lab.local",
                "source": "ot",
                "event_id": "modbus",
                "message": "modbus fc=16 write multiple registers unit=1",
            },
            {
                "ts": now,
                "host": "broker.lab.local",
                "source": "mqtt",
                "event_id": "connack",
                "message": "mqtt CONNACK rejected return_code=5 not authorized",
            },
        ],
    }
