# Nightly autopilot (#100): a small cron engine + run ledger for unattended runs.
#
# "Needs cron" usually means "shell out to cron". That is a bad fit inside a
# container: cron has no idea about engagement scope, no run history, no
# stop button, and a missed run silently disappears. This module implements the
# useful subset of cron (5 fields, ranges, lists, steps, names, macros) with
# next-run calculation, a SQLite run ledger, and a scheduler that calls the same
# scope-gated autopilot endpoint a human would use. It is disabled unless
# H4K_SCHEDULER=1, so the default single-session behaviour is unchanged.
from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

logger = logging.getLogger("h4k.nightly")

MONTH_NAMES = {
    name: index
    for index, name in enumerate(
        [
            "jan",
            "feb",
            "mar",
            "apr",
            "may",
            "jun",
            "jul",
            "aug",
            "sep",
            "oct",
            "nov",
            "dec",
        ],
        start=1,
    )
}
DOW_NAMES = {
    name: index
    for index, name in enumerate(
        ["sun", "mon", "tue", "wed", "thu", "fri", "sat"], start=0
    )
}
MACROS = {
    "@yearly": "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly": "0 0 1 * *",
    "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *",
    "@midnight": "0 0 * * *",
    "@hourly": "0 * * * *",
    "@nightly": "0 3 * * *",
}


class CronError(ValueError):
    pass


@dataclass(frozen=True)
class CronSchedule:
    minute: frozenset[int]
    hour: frozenset[int]
    day: frozenset[int]
    month: frozenset[int]
    weekday: frozenset[int]
    dom_restricted: bool
    dow_restricted: bool
    expression: str

    def matches(self, moment: datetime) -> bool:
        if moment.minute not in self.minute or moment.hour not in self.hour:
            return False
        if moment.month not in self.month:
            return False
        dom_ok = moment.day in self.day
        dow_ok = (moment.isoweekday() % 7) in self.weekday
        if self.dom_restricted and self.dow_restricted:
            return dom_ok or dow_ok
        return dom_ok and dow_ok


def _expand_field(
    raw: str, minimum: int, maximum: int, names: dict[str, int] | None = None
) -> tuple[frozenset[int], bool]:
    if raw == "*":
        return frozenset(range(minimum, maximum + 1)), False
    values: set[int] = set()
    restricted = True
    for part in raw.split(","):
        part = part.strip()
        if not part:
            raise CronError("empty list item in cron field")
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            try:
                step = int(step_text)
            except ValueError as exc:
                raise CronError(f"bad step: {step_text}") from exc
            if step <= 0:
                raise CronError("step must be positive")
        if part == "*":
            start, end = minimum, maximum
        elif "-" in part:
            left, right = part.split("-", 1)
            start = _value(left, names, minimum)
            end = _value(right, names, minimum)
            if end < start:
                raise CronError(f"range end before start: {part}")
        else:
            start = end = _value(part, names, minimum)
        for value in range(start, end + 1, step):
            if value < minimum or value > maximum:
                raise CronError(f"value {value} outside {minimum}-{maximum}")
            values.add(value)
    return frozenset(values), restricted


def _value(text: str, names: dict[str, int] | None, minimum: int) -> int:
    text = text.strip()
    if names and text.lower() in names:
        return names[text.lower()]
    try:
        return int(text)
    except ValueError as exc:
        raise CronError(f"bad cron value: {text!r}") from exc


def parse_cron(expression: str) -> CronSchedule:
    expr = (expression or "").strip()
    if not expr:
        raise CronError("cron expression is required")
    if expr.startswith("@"):
        base = MACROS.get(expr.lower())
        if base is None:
            raise CronError(f"unknown cron macro: {expr}")
        expr = base
    parts = expr.split()
    if len(parts) != 5:
        raise CronError(
            "cron must have five fields (minute hour day-of-month month day-of-week)"
        )
    minute, _ = _expand_field(parts[0], 0, 59)
    hour, _ = _expand_field(parts[1], 0, 23)
    day, dom_restricted = _expand_field(parts[2], 1, 31)
    month, _ = _expand_field(parts[3], 1, 12, MONTH_NAMES)
    weekday_raw, dow_restricted = _expand_field(parts[4], 0, 7, DOW_NAMES)
    weekday = frozenset(0 if day_value == 7 else day_value for day_value in weekday_raw)
    return CronSchedule(
        minute=minute,
        hour=hour,
        day=day,
        month=month,
        weekday=weekday,
        dom_restricted=dom_restricted,
        dow_restricted=dow_restricted,
        expression=expression.strip(),
    )


def next_run(
    expression: str, after: datetime | None = None, *, tz: str = "UTC"
) -> datetime:
    """Next matching minute, returned in UTC."""
    schedule = parse_cron(expression)
    zone = _zone(tz)
    base = after or datetime.now(UTC)
    if base.tzinfo is None:
        base = base.replace(tzinfo=UTC)
    local = base.astimezone(zone).replace(second=0, microsecond=0) + timedelta(
        minutes=1
    )
    # Five years of minutes is far beyond any sane schedule; stop rather than
    # spin forever on an impossible expression such as "0 0 31 2 *".
    limit = local + timedelta(days=366 * 5)
    while local <= limit:
        if schedule.matches(local):
            return local.astimezone(UTC)
        local += timedelta(minutes=1)
    raise CronError("cron expression never matches within five years")


def upcoming(
    expression: str, count: int = 5, after: datetime | None = None, tz: str = "UTC"
) -> list[str]:
    runs = []
    cursor = after or datetime.now(UTC)
    for _ in range(max(1, min(int(count), 20))):
        cursor = next_run(expression, cursor, tz=tz)
        runs.append(cursor.isoformat(timespec="seconds"))
    return runs


def _zone(tz: str) -> ZoneInfo:
    try:
        return ZoneInfo(tz or "UTC")
    except Exception as exc:
        raise CronError(f"unknown timezone: {tz}") from exc


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS schedules (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    cron          TEXT NOT NULL,
    engagement_id TEXT NOT NULL DEFAULT '',
    deep_web      INTEGER NOT NULL DEFAULT 0,
    enabled       INTEGER NOT NULL DEFAULT 1,
    timezone      TEXT NOT NULL DEFAULT 'UTC',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    last_run      TEXT,
    next_run      TEXT,
    last_status   TEXT NOT NULL DEFAULT 'never',
    last_job_id   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS runs (
    id          TEXT PRIMARY KEY,
    schedule_id TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    job_id      TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_runs_schedule ON runs(schedule_id, started_at);
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class ScheduleStore:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else self._default_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    @staticmethod
    def _default_path() -> Path:
        runtime = Path("/opt/h4k/data")
        if runtime.is_dir():
            return runtime / "automation.db"
        return Path(__file__).resolve().parent.parent / "data" / "automation.db"

    def _connect(self) -> Any:
        import sqlite3

        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    # -- CRUD --------------------------------------------------------------
    def create(
        self,
        name: str,
        cron: str,
        *,
        engagement_id: str = "",
        deep_web: bool = False,
        enabled: bool = True,
        timezone: str = "UTC",
    ) -> dict[str, Any]:
        if not name.strip():
            raise ValueError("schedule name is required")
        parse_cron(cron)
        _zone(timezone)
        now = _now_iso()
        schedule_id = uuid.uuid4().hex[:12]
        next_at = next_run(cron, tz=timezone).isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO schedules (id, name, cron, engagement_id, deep_web, "
                "enabled, timezone, created_at, updated_at, next_run, last_status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'never')",
                (
                    schedule_id,
                    name.strip(),
                    cron.strip(),
                    engagement_id,
                    1 if deep_web else 0,
                    1 if enabled else 0,
                    timezone,
                    now,
                    now,
                    next_at,
                ),
            )
            conn.commit()
        return self.get(schedule_id)  # type: ignore[return-value]

    def list_all(self) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM schedules ORDER BY created_at DESC"
            ).fetchall()
        return [self._schedule(row) for row in rows]

    def get(self, schedule_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM schedules WHERE id = ?", (schedule_id,)
            ).fetchone()
        return self._schedule(row) if row else None

    def update(self, schedule_id: str, changes: dict[str, Any]) -> dict[str, Any]:
        schedule = self.get(schedule_id)
        if schedule is None:
            raise KeyError("schedule not found")
        cron = str(changes.get("cron") or schedule["cron"])
        timezone = str(changes.get("timezone") or schedule["timezone"])
        parse_cron(cron)
        _zone(timezone)
        enabled = bool(changes.get("enabled", schedule["enabled"]))
        deep_web = bool(changes.get("deep_web", schedule["deep_web"]))
        name = str(changes.get("name") or schedule["name"])
        engagement_id = str(changes.get("engagement_id", schedule["engagement_id"]))
        next_at = (
            next_run(cron, tz=timezone).isoformat(timespec="seconds")
            if enabled
            else None
        )
        with self._connect() as conn:
            conn.execute(
                "UPDATE schedules SET name=?, cron=?, engagement_id=?, deep_web=?, "
                "enabled=?, timezone=?, updated_at=?, next_run=? WHERE id=?",
                (
                    name,
                    cron,
                    engagement_id,
                    1 if deep_web else 0,
                    1 if enabled else 0,
                    timezone,
                    _now_iso(),
                    next_at,
                    schedule_id,
                ),
            )
            conn.commit()
        return self.get(schedule_id)  # type: ignore[return-value]

    def delete(self, schedule_id: str) -> bool:
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM schedules WHERE id = ?", (schedule_id,))
            conn.execute("DELETE FROM runs WHERE schedule_id = ?", (schedule_id,))
            conn.commit()
            return cursor.rowcount > 0

    def due(self, now: datetime | None = None) -> list[dict[str, Any]]:
        moment = (
            (now or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
        )
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM schedules WHERE enabled=1 AND next_run IS NOT NULL "
                "AND next_run <= ? ORDER BY next_run",
                (moment,),
            ).fetchall()
        return [self._schedule(row) for row in rows]

    # -- runs --------------------------------------------------------------
    def start_run(self, schedule_id: str) -> dict[str, Any]:
        run_id = uuid.uuid4().hex[:12]
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO runs (id, schedule_id, started_at, status) "
                "VALUES (?, ?, ?, 'running')",
                (run_id, schedule_id, _now_iso()),
            )
            conn.execute(
                "UPDATE schedules SET last_run=?, last_status='running' WHERE id=?",
                (_now_iso(), schedule_id),
            )
            conn.commit()
        return {"id": run_id, "schedule_id": schedule_id, "status": "running"}

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        job_id: str = "",
        summary: str = "",
        error: str = "",
    ) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT schedule_id FROM runs WHERE id=?", (run_id,)
            ).fetchone()
            if row is None:
                raise KeyError("run not found")
            schedule_id = row["schedule_id"]
            conn.execute(
                "UPDATE runs SET finished_at=?, status=?, job_id=?, summary=?, "
                "error=? WHERE id=?",
                (_now_iso(), status, job_id, summary[:4000], error[:4000], run_id),
            )
            schedule = conn.execute(
                "SELECT cron, timezone FROM schedules WHERE id=?", (schedule_id,)
            ).fetchone()
            next_at = None
            if schedule is not None:
                try:
                    next_at = next_run(
                        schedule["cron"], tz=schedule["timezone"] or "UTC"
                    ).isoformat(timespec="seconds")
                except CronError:  # pragma: no cover - validated on write
                    next_at = None
            conn.execute(
                "UPDATE schedules SET last_status=?, last_job_id=?, next_run=? "
                "WHERE id=?",
                (status, job_id, next_at, schedule_id),
            )
            conn.commit()
        return {"id": run_id, "status": status, "job_id": job_id}

    def runs(self, schedule_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            if schedule_id:
                rows = conn.execute(
                    "SELECT * FROM runs WHERE schedule_id=? "
                    "ORDER BY started_at DESC LIMIT ?",
                    (schedule_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM runs ORDER BY started_at DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _schedule(row: Any) -> dict[str, Any]:
        data = dict(row)
        data["deep_web"] = bool(data.get("deep_web"))
        data["enabled"] = bool(data.get("enabled"))
        return data


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_autopilot(schedule: dict[str, Any]) -> dict[str, Any]:
    """Drive the same scope-gated autopilot a human would start from the UI."""
    import app_state
    import routers.scan as scan

    engagement_id = str(schedule.get("engagement_id") or "")
    if not engagement_id:
        return {"ok": False, "error": "schedule has no engagement_id (scope)"}
    app_state.active_engagement_id = engagement_id
    try:
        started = scan.autopilot_start({"deep_web": bool(schedule.get("deep_web"))})
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    job_id = str(started.get("job_id") or "")
    deadline = time.monotonic() + float(os.environ.get("H4K_NIGHTLY_TIMEOUT", "21600"))
    while time.monotonic() < deadline:
        status = scan.autopilot_status()
        if status.get("status") != "running":
            return {
                "ok": status.get("status") in {"complete", "aborted"},
                "job_id": job_id,
                "status": status.get("status"),
                "hosts": len(status.get("hosts") or {}),
                "message": status.get("message", ""),
            }
        time.sleep(float(os.environ.get("H4K_NIGHTLY_POLL", "5")))
    return {"ok": False, "job_id": job_id, "error": "autopilot timed out"}


class NightlyScheduler:
    def __init__(
        self,
        store: ScheduleStore | None = None,
        runner: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    ) -> None:
        self.store = store or ScheduleStore()
        self.runner = runner or run_autopilot
        self._task: asyncio.Task[None] | None = None
        self._stop = threading.Event()
        self.running = False

    def tick(self, now: datetime | None = None) -> list[dict[str, Any]]:
        results = []
        for schedule in self.store.due(now):
            results.append(self.run_schedule(schedule))
        return results

    def run_schedule(self, schedule: dict[str, Any]) -> dict[str, Any]:
        run = self.store.start_run(schedule["id"])
        try:
            outcome = self.runner(schedule) or {}
        except Exception as exc:  # pragma: no cover - defensive
            outcome = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        status = (
            "complete"
            if outcome.get("ok") and outcome.get("status") != "aborted"
            else "error"
        )
        summary = (
            f"{outcome.get('status', '')} hosts={outcome.get('hosts', 0)} "
            f"job={outcome.get('job_id', '')}"
        ).strip()
        self.store.finish_run(
            run["id"],
            status=status,
            job_id=str(outcome.get("job_id") or ""),
            summary=summary,
            error=str(outcome.get("error") or ""),
        )
        logger.warning(
            "[nightly] %s (%s) -> %s", schedule["name"], schedule["id"], status
        )
        return {**run, **outcome, "status": status}

    def run_now(self, schedule_id: str) -> dict[str, Any]:
        schedule = self.store.get(schedule_id)
        if schedule is None:
            raise KeyError("schedule not found")
        return self.run_schedule(schedule)

    async def serve(self, interval: float = 20.0) -> None:
        self.running = True
        try:
            while not self._stop.is_set():
                try:
                    await asyncio.to_thread(self.tick)
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning("scheduler tick failed: %s", exc)
                await asyncio.sleep(max(5.0, interval))
        finally:
            self.running = False

    def start(self, interval: float = 20.0) -> asyncio.Task[None]:
        if self._task is None or self._task.done():
            self._stop.clear()
            self._task = asyncio.create_task(self.serve(interval))
        return self._task

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError, Exception):
                await self._task
            self._task = None


def scheduler_enabled() -> bool:
    return os.environ.get("H4K_SCHEDULER", "0").lower() in {"1", "true", "yes", "on"}


def scheduler_interval() -> float:
    return float(os.environ.get("H4K_SCHEDULER_INTERVAL", "20"))
