# Persistent engagement store: the memory h4k was missing.
#
# A scan is per-target and dies with the process. A real engagement spans hours
# and hundreds of assets, and the operator needs the accumulated picture:
# every host, every service, every credential, and — critically — *where each
# credential came from and where it also works*. That provenance is what turns
# a list of vulns into a set of attack paths.
#
# Scope is enforced here, not in the UI: an engagement declares the CIDRs it is
# authorized for, and every write/read path filters through it. Nothing outside
# scope can be recorded or replayed, so a mistyped target in the UI cannot
# silently widen the engagement.
import ipaddress
import json
import logging
import re
import sqlite3
import threading
import uuid
from collections.abc import Iterable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("h4k.engagement")

_RUNTIME_DIR = Path("/opt/h4k/data")
DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"
DB_NAME = "engagements.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    scope       TEXT NOT NULL DEFAULT '[]',
    notes       TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assets (
    engagement_id TEXT NOT NULL,
    host          TEXT NOT NULL,
    os            TEXT,
    vendor        TEXT,
    technology    TEXT NOT NULL DEFAULT '[]',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    PRIMARY KEY (engagement_id, host)
);
CREATE TABLE IF NOT EXISTS services (
    engagement_id TEXT NOT NULL,
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    service       TEXT,
    version       TEXT,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    PRIMARY KEY (engagement_id, host, port, service)
);
CREATE TABLE IF NOT EXISTS credentials (
    engagement_id TEXT NOT NULL,
    user          TEXT NOT NULL,
    password      TEXT NOT NULL,
    service       TEXT NOT NULL DEFAULT '',
    first_seen    TEXT NOT NULL,
    last_verified TEXT,
    PRIMARY KEY (engagement_id, user, password, service)
);
-- Where each credential actually grants access. Separate from `credentials`
-- because one credential usually works on *many* hosts, and that fan-out is
-- the lateral-movement picture. `credentials` alone cannot hold it: its key is
-- (user, password, service), so a second host would overwrite the first.
CREATE TABLE IF NOT EXISTS cred_access (
    engagement_id TEXT NOT NULL,
    user          TEXT NOT NULL,
    password      TEXT NOT NULL,
    service       TEXT NOT NULL DEFAULT '',
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    verified      INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_verified TEXT,
    PRIMARY KEY (engagement_id, user, password, service, host, port)
);
CREATE TABLE IF NOT EXISTS vulns (
    engagement_id TEXT NOT NULL,
    host          TEXT NOT NULL,
    name          TEXT NOT NULL,
    severity      TEXT,
    cwe           TEXT,
    module        TEXT,
    reference     TEXT,
    first_seen    TEXT NOT NULL,
    PRIMARY KEY (engagement_id, host, name)
);
-- Attempt ledger. Deliberately NOT the credentials table: a failed login is
-- not a credential, and recording it as one would put a bogus credential edge
-- in the graph and inflate the credential count.
CREATE TABLE IF NOT EXISTS attempts (
    engagement_id TEXT NOT NULL,
    host          TEXT NOT NULL,
    port          INTEGER NOT NULL,
    service       TEXT NOT NULL,
    user          TEXT NOT NULL,
    password      TEXT NOT NULL,
    result        TEXT NOT NULL,
    module        TEXT,
    at            TEXT NOT NULL,
    PRIMARY KEY (engagement_id, host, port, service, user, password)
);
CREATE INDEX IF NOT EXISTS idx_assets_eng ON assets(engagement_id);
CREATE INDEX IF NOT EXISTS idx_services_eng ON services(engagement_id);
CREATE INDEX IF NOT EXISTS idx_creds_eng ON credentials(engagement_id);
CREATE INDEX IF NOT EXISTS idx_access_eng ON cred_access(engagement_id);
CREATE INDEX IF NOT EXISTS idx_vulns_eng ON vulns(engagement_id);
CREATE INDEX IF NOT EXISTS idx_attempts_eng ON attempts(engagement_id);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def db_path() -> Path:
    """Runtime data dir in the container, repo data dir on the host."""
    if _RUNTIME_DIR.is_dir():
        _RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        return _RUNTIME_DIR / DB_NAME
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR / DB_NAME


class ScopeError(ValueError):
    """Raised when a host falls outside the engagement's authorized scope."""


class EngagementStore:
    """Thread-safe SQLite store. One connection per call, serialized by a lock
    because the scan pipeline runs in FastAPI's threadpool."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path else db_path()
        self._lock = threading.RLock()
        self._init_db()

    # ---- plumbing ----------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(SCHEMA)
        with suppress(OSError):  # non-POSIX / read-only fs
            self.path.chmod(0o600)  # holds verified credentials

    def _query(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock, self._connect() as conn:
            return list(conn.execute(sql, args).fetchall())

    def _write(self, sql: str, args: tuple = ()) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(sql, args)
            conn.commit()

    def _exists(self, sql: str, args: tuple = ()) -> bool:
        with self._lock, self._connect() as conn:
            return conn.execute(sql, args).fetchone() is not None

    def _scalar(self, sql: str, args: tuple = ()) -> Any:
        with self._lock, self._connect() as conn:
            row = conn.execute(sql, args).fetchone()
        return row[0] if row else None

    # ---- engagements -------------------------------------------------------

    def create_engagement(
        self, name: str, scope: list[str] | None = None, notes: str = ""
    ) -> dict[str, Any]:
        name = (name or "").strip()
        if not name:
            raise ValueError("name required")
        scope_list = _normalize_scope(scope)
        if not scope_list:
            raise ValueError("scope required: list at least one IP or CIDR")
        for net in scope_list:
            if not isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                raise ValueError(f"scope entry is not an IP/CIDR: {net}")
        eid = uuid.uuid4().hex[:12]
        ts = _now()
        self._write(
            "INSERT INTO engagements (id, name, scope, notes, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?)",
            (eid, name, json.dumps([str(n) for n in scope_list]), notes, ts, ts),
        )
        return self.get_engagement(eid)  # type: ignore[return-value]

    def list_engagements(self) -> list[dict[str, Any]]:
        rows = self._query("SELECT * FROM engagements ORDER BY created_at DESC")
        return [self._row_to_engagement(r) for r in rows]

    def get_engagement(self, engagement_id: str) -> dict[str, Any] | None:
        rows = self._query("SELECT * FROM engagements WHERE id=?", (engagement_id,))
        return self._row_to_engagement(rows[0]) if rows else None

    def delete_engagement(self, engagement_id: str) -> bool:
        # Explicit statements rather than an f-string over a table name: the
        # table list is fixed, so there is no reason to assemble SQL at all.
        for sql in (
            "DELETE FROM assets WHERE engagement_id=?",
            "DELETE FROM services WHERE engagement_id=?",
            "DELETE FROM credentials WHERE engagement_id=?",
            "DELETE FROM cred_access WHERE engagement_id=?",
            "DELETE FROM vulns WHERE engagement_id=?",
            "DELETE FROM attempts WHERE engagement_id=?",
        ):
            self._write(sql, (engagement_id,))
        before = self._scalar(
            "SELECT COUNT(*) FROM engagements WHERE id=?", (engagement_id,)
        )
        self._write("DELETE FROM engagements WHERE id=?", (engagement_id,))
        return bool(before)

    @staticmethod
    def _row_to_engagement(row: sqlite3.Row) -> dict[str, Any]:
        d = dict(row)
        d["scope"] = json.loads(d.get("scope") or "[]")
        return d

    # ---- scope enforcement -------------------------------------------------

    def scope_of(self, engagement_id: str) -> list[str]:
        eng = self.get_engagement(engagement_id)
        return list(eng["scope"]) if eng else []

    def in_scope(self, engagement_id: str, host: str) -> bool:
        """True if `host` is covered by the engagement's authorized scope."""
        for entry in self.scope_of(engagement_id):
            try:
                net = ipaddress.ip_network(entry, strict=False)
                addr = ipaddress.ip_address(host)
            except ValueError:
                continue
            if addr.version == net.version and addr in net:
                return True
        return False

    def _require_scope(self, engagement_id: str, host: str) -> None:
        if not self.in_scope(engagement_id, host):
            raise ScopeError(
                f"{host} is outside the authorized scope of engagement "
                f"{engagement_id}"
            )

    # ---- ingest ------------------------------------------------------------

    def ingest_scan(self, engagement_id: str, report: dict[str, Any]) -> dict[str, Any]:
        """Absorb a scan report into the engagement graph.

        Out-of-scope hosts are skipped (not raised) so one wide scan target
        cannot poison an engagement; the count is reported so the operator can
        see that it happened.
        """
        if not self.get_engagement(engagement_id):
            raise ValueError("unknown engagement")
        added = {"assets": 0, "services": 0, "credentials": 0, "vulns": 0}
        skipped: list[str] = []

        fps = {f.get("host"): f for f in report.get("fingerprints") or []}
        for host in report.get("hosts") or []:
            addr = host.get("address")
            if not addr or not self.in_scope(engagement_id, addr):
                if addr:
                    skipped.append(addr)
                continue
            fp = fps.get(addr, {})
            added["assets"] += self.upsert_asset(
                engagement_id,
                addr,
                os=fp.get("os") or host.get("os"),
                vendor=fp.get("vendor"),
                technology=fp.get("technology") or [],
            )
            for svc in host.get("services") or []:
                if self.upsert_service(engagement_id, addr, svc):
                    added["services"] += 1

        for cred in report.get("credentials") or []:
            addr = cred.get("host")
            if not addr or not self.in_scope(engagement_id, addr):
                continue
            if self.record_credential(
                engagement_id,
                user=cred.get("user", ""),
                password=cred.get("password", ""),
                service=cred.get("service"),
                origin_host=addr,
                origin_port=cred.get("port"),
                verified=bool(cred.get("verified")),
            ):
                added["credentials"] += 1

        for vuln in report.get("vulns") or []:
            addr = vuln.get("host")
            if not addr or not self.in_scope(engagement_id, addr):
                continue
            if self.record_vuln(engagement_id, addr, vuln):
                added["vulns"] += 1

        self._touch(engagement_id)
        return {"added": added, "skipped_out_of_scope": sorted(set(skipped))}

    def upsert_asset(
        self,
        engagement_id: str,
        host: str,
        os: str | None = None,
        vendor: str | None = None,
        technology: Iterable[str] = (),
    ) -> int:
        self._require_scope(engagement_id, host)
        ts = _now()
        is_new = not self._exists(
            "SELECT 1 FROM assets WHERE engagement_id=? AND host=?",
            (engagement_id, host),
        )
        self._write(
            "INSERT INTO assets (engagement_id, host, os, vendor, technology,"
            " first_seen, last_seen) VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(engagement_id, host) DO UPDATE SET"
            " os=COALESCE(excluded.os, assets.os),"
            " vendor=COALESCE(excluded.vendor, assets.vendor),"
            " technology=CASE WHEN excluded.technology='[]' THEN assets.technology"
            " ELSE excluded.technology END,"
            " last_seen=excluded.last_seen",
            (
                engagement_id,
                host,
                os,
                vendor,
                json.dumps(list(technology)),
                ts,
                ts,
            ),
        )
        return int(is_new)

    def upsert_service(self, engagement_id: str, host: str, svc: dict[str, Any]) -> int:
        self._require_scope(engagement_id, host)
        port = int(svc.get("port") or 0)
        if not port:
            return 0
        ts = _now()
        is_new = not self._exists(
            "SELECT 1 FROM services WHERE engagement_id=? AND host=? AND port=?"
            " AND service IS ?",
            (engagement_id, host, port, svc.get("service")),
        )
        self._write(
            "INSERT INTO services (engagement_id, host, port, service, version,"
            " first_seen, last_seen) VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(engagement_id, host, port, service) DO UPDATE SET"
            " version=COALESCE(excluded.version, services.version),"
            " last_seen=excluded.last_seen",
            (
                engagement_id,
                host,
                port,
                svc.get("service"),
                svc.get("version"),
                ts,
                ts,
            ),
        )
        return int(is_new)

    def record_credential(
        self,
        engagement_id: str,
        user: str,
        password: str,
        service: str | None = None,
        origin_host: str | None = None,
        origin_port: int | None = None,
        verified: bool = False,
    ) -> int:
        """Record a credential and, when known, one host it grants access to.

        The credential and the access are separate upserts: a password that
        works on five hosts is one credential and five access rows, which is what
        lets `graph()` report real lateral movement instead of guessing.
        """
        if not user or password is None:
            return 0
        if origin_host:
            self._require_scope(engagement_id, origin_host)
        svc = service or ""
        ts = _now()
        is_new = not self._exists(
            "SELECT 1 FROM credentials WHERE engagement_id=? AND user=? AND password=?"
            " AND service=?",
            (engagement_id, user, password, svc),
        )
        self._write(
            "INSERT INTO credentials (engagement_id, user, password, service,"
            " first_seen, last_verified) VALUES (?,?,?,?,?,?)"
            " ON CONFLICT(engagement_id, user, password, service) DO UPDATE SET"
            " last_verified=COALESCE(excluded.last_verified,"
            " credentials.last_verified)",
            (engagement_id, user, password, svc, ts, ts if verified else None),
        )
        if origin_host:
            self._write(
                "INSERT INTO cred_access (engagement_id, user, password, service,"
                " host, port, verified, first_seen, last_verified)"
                " VALUES (?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(engagement_id, user, password, service, host, port)"
                " DO UPDATE SET verified=MAX(cred_access.verified, excluded.verified),"
                " last_verified=COALESCE(excluded.last_verified,"
                " cred_access.last_verified)",
                (
                    engagement_id,
                    user,
                    password,
                    svc,
                    origin_host,
                    int(origin_port or 0),
                    int(verified),
                    ts,
                    ts if verified else None,
                ),
            )
        return int(is_new)

    def record_vuln(self, engagement_id: str, host: str, vuln: dict[str, Any]) -> int:
        self._require_scope(engagement_id, host)
        name = vuln.get("name") or vuln.get("title") or "unknown"
        is_new = not self._exists(
            "SELECT 1 FROM vulns WHERE engagement_id=? AND host=? AND name=?",
            (engagement_id, host, name),
        )
        self._write(
            "INSERT INTO vulns (engagement_id, host, name, severity, cwe, module,"
            " reference, first_seen) VALUES (?,?,?,?,?,?,?,?)"
            " ON CONFLICT(engagement_id, host, name) DO UPDATE SET"
            " severity=COALESCE(excluded.severity, vulns.severity)",
            (
                engagement_id,
                host,
                name,
                vuln.get("severity"),
                vuln.get("cwe"),
                vuln.get("module"),
                vuln.get("reference"),
                _now(),
            ),
        )
        return int(is_new)

    def _touch(self, engagement_id: str) -> None:
        self._write(
            "UPDATE engagements SET updated_at=? WHERE id=?", (_now(), engagement_id)
        )

    def touch(self, engagement_id: str) -> None:
        self._touch(engagement_id)

    # ---- attempt ledger ----------------------------------------------------

    def record_attempt(
        self,
        engagement_id: str,
        host: str,
        port: int,
        service: str,
        user: str,
        password: str,
        result: str,
        module: str | None = None,
    ) -> None:
        """Log one login attempt (hit or miss) so it is never repeated."""
        self._require_scope(engagement_id, host)
        self._write(
            "INSERT INTO attempts (engagement_id, host, port, service, user,"
            " password, result, module, at) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(engagement_id, host, port, service, user, password)"
            " DO UPDATE SET result=excluded.result, at=excluded.at",
            (
                engagement_id,
                host,
                int(port or 0),
                service or "",
                user,
                password,
                result,
                module,
                _now(),
            ),
        )

    def attempted_pairs(
        self, engagement_id: str
    ) -> set[tuple[str, int, str, str, str]]:
        rows = self._query(
            "SELECT host, port, service, user, password FROM attempts"
            " WHERE engagement_id=?",
            (engagement_id,),
        )
        return {
            (r["host"], r["port"], r["service"], r["user"], r["password"]) for r in rows
        }

    def attempts(self, engagement_id: str) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM attempts WHERE engagement_id=? ORDER BY at DESC",
            (engagement_id,),
        )
        return [dict(r) for r in rows]

    # ---- reads -------------------------------------------------------------

    def assets(self, engagement_id: str) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM assets WHERE engagement_id=? ORDER BY host", (engagement_id,)
        )
        out = []
        for r in rows:
            d = dict(r)
            d["technology"] = json.loads(d.get("technology") or "[]")
            d["services"] = self.services(engagement_id, d["host"])
            out.append(d)
        return out

    def services(
        self, engagement_id: str, host: str | None = None
    ) -> list[dict[str, Any]]:
        if host:
            rows = self._query(
                "SELECT * FROM services WHERE engagement_id=? AND host=?"
                " ORDER BY port",
                (engagement_id, host),
            )
        else:
            rows = self._query(
                "SELECT * FROM services WHERE engagement_id=? ORDER BY host, port",
                (engagement_id,),
            )
        return [dict(r) for r in rows]

    def credentials(self, engagement_id: str) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM credentials WHERE engagement_id=? ORDER BY first_seen",
            (engagement_id,),
        )
        out = []
        for r in rows:
            d = dict(r)
            d["verified"] = bool(self.store_has_access(engagement_id, d))
            d["hosts"] = self.access_hosts(
                engagement_id, d["user"], d["password"], d["service"]
            )
            out.append(d)
        return out

    def store_has_access(self, engagement_id: str, cred: dict[str, Any]) -> bool:
        return bool(
            self._scalar(
                "SELECT COUNT(*) FROM cred_access WHERE engagement_id=? AND user=?"
                " AND password=? AND service=? AND verified=1",
                (
                    engagement_id,
                    cred["user"],
                    cred["password"],
                    cred.get("service") or "",
                ),
            )
        )

    def access(self, engagement_id: str) -> list[dict[str, Any]]:
        """Every (credential, host) access pair — the lateral-movement ledger."""
        rows = self._query(
            "SELECT * FROM cred_access WHERE engagement_id=? ORDER BY first_seen",
            (engagement_id,),
        )
        return [dict(r) for r in rows]

    def access_hosts(
        self, engagement_id: str, user: str, password: str, service: str
    ) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT host, port, verified FROM cred_access WHERE engagement_id=?"
            " AND user=? AND password=? AND service=? AND verified=1"
            " ORDER BY first_seen",
            (engagement_id, user, password, service or ""),
        )
        return [dict(r) for r in rows]

    def verified_credentials(self, engagement_id: str) -> list[dict[str, Any]]:
        return [c for c in self.credentials(engagement_id) if c.get("verified")]

    def vulns(self, engagement_id: str) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT * FROM vulns WHERE engagement_id=? ORDER BY host, name",
            (engagement_id,),
        )
        return [dict(r) for r in rows]

    def summary(self, engagement_id: str) -> dict[str, Any]:
        creds = self.credentials(engagement_id)
        verified = [c for c in creds if c.get("verified")]
        access = [a for a in self.access(engagement_id) if a.get("verified")]
        return {
            "engagement_id": engagement_id,
            "assets": int(
                self._scalar(
                    "SELECT COUNT(*) FROM assets WHERE engagement_id=?",
                    (engagement_id,),
                )
                or 0
            ),
            "services": int(
                self._scalar(
                    "SELECT COUNT(*) FROM services WHERE engagement_id=?",
                    (engagement_id,),
                )
                or 0
            ),
            "vulns": int(
                self._scalar(
                    "SELECT COUNT(*) FROM vulns WHERE engagement_id=?", (engagement_id,)
                )
                or 0
            ),
            "credentials": len(creds),
            "verified_credentials": len(verified),
            "access_grants": len(access),
            # a credential reaching more than one host is the lateral-movement
            # signal; a single-host fan-out is just a login.
            "pivotable_credentials": sum(1 for c in verified if len(c["hosts"]) > 1),
            "pivot_hosts": len(
                {a["host"] for c in verified for a in c["hosts"]}
                - {c["hosts"][0]["host"] for c in verified if c["hosts"]}
            ),
        }

    def graph(self, engagement_id: str) -> dict[str, Any]:
        """hosts -> services, plus credential-access edges with provenance.

        Every `credential` edge below is backed by a login we actually verified
        and recorded in `cred_access`. Nothing here is inferred from "these hosts
        both run ssh" — a host appears in `reaches` only because the credential
        was accepted there. Unverified fan-out would be a guess, and this tool
        does not report guesses as reachability.
        """
        assets = self.assets(engagement_id)
        nodes = [
            {
                "id": a["host"],
                "label": a["host"],
                "type": "host",
                "os": a.get("os"),
                "vendor": a.get("vendor"),
                "service_count": len(a["services"]),
            }
            for a in assets
        ]
        edges = [
            {
                "source": s["host"],
                "target": f"{s['host']}:{s['port']}",
                "type": "service",
                "port": s["port"],
                "service": s.get("service"),
            }
            for s in self.services(engagement_id)
        ]
        for cred in self.credentials(engagement_id):
            if not cred.get("verified") or not cred["hosts"]:
                continue
            hosts = cred["hosts"]
            origin = hosts[0]["host"]
            label = f"{cred['user']}@{cred.get('service') or 'any'}"
            for access in hosts:
                edges.append(
                    {
                        "source": access["host"],
                        "target": label,
                        "type": "credential",
                        "user": cred["user"],
                        "service": cred.get("service"),
                        "verified": True,
                    }
                )
            if len(hosts) > 1:
                edges.append(
                    {
                        "source": origin,
                        "target": label,
                        "type": "pivot",
                        "user": cred["user"],
                        "service": cred.get("service"),
                        "reaches": sorted(h["host"] for h in hosts[1:]),
                        "verified": True,
                    }
                )
        return {"nodes": nodes, "edges": edges, "summary": self.summary(engagement_id)}


def _normalize_scope(scope: list[str] | None) -> list[Any]:
    """Accept bare IPs and CIDRs; return networks. Deduped, order-stable."""
    out: list[Any] = []
    for entry in scope or []:
        entry = str(entry).strip()
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            # hostname entries are not enforceable as a network; keep them out
            # of the numeric scope but let the caller notice via validation
            continue
        if net not in out:
            out.append(net)
    return out


def parse_scope(text: str) -> list[str]:
    """Parse a human-entered scope string ("10.0.0.0/24, 10.1.1.5")."""
    return [p for p in re.split(r"[,\s]+", text.strip()) if p]
