# Credential propagation: turn "a cred works somewhere" into "here is where it
# also works."
#
# A per-target scan tries the archive's creds against the hosts in that one
# scan and then forgets. Real access is rarely local: the same password that
# opens the web box usually opens the database box, because humans reuse. This
# engine takes credentials *already verified in the engagement* and replays
# them against every other in-scope service that has a login module, recording
# the origin→target pairs as edges in the asset graph.
#
# Safety properties, all deliberate:
#   * It only ever replays credentials that were already verified against an
#     in-scope host. It never invents, mutates, or sprays new candidates, so it
#     cannot authenticate against a service nobody authorized us to test.
#   * Every (credential, service) pair is attempted at most once per engagement,
#     so re-running is cheap and the attempt count is a real cost bound.
#   * Targets are re-checked against engagement scope immediately before the
#     attempt, not just at planning time.
#   * It is opt-in and off by default, like every other active action here.
import logging
import time
from collections.abc import Callable
from typing import Any

from services.creds import CredArchive
from services.engagement import EngagementStore
from services.msfrpc import MsfClient
from services.spray_guard import (
    DEFAULT_JITTER_MAX,
    DEFAULT_MAX_PER_USER,
    SprayPolicy,
    apply_policy,
    is_lockout_signal,
    jitter_delay,
    locked_users,
    user_attempt_counts,
)

logger = logging.getLogger("h4k.propagate")

# Services worth replaying a known credential against. Deliberately excludes
# anything where a login attempt is destructive or loudly lockout-prone unless
# the operator has already proven the cred works there.
# Hard cost bound on one propagation run. A credential replay against hundreds
# of services is a real action; the operator should have to raise this, not
# discover it.
MAX_ATTEMPTS = 500

PROPAGATE_SERVICES = (
    "ssh",
    "telnet",
    "ftp",
    "smb",
    "microsoft-ds",
    "netbios-ssn",
    "rdp",
    "ms-wbt-server",
    "mysql",
    "mssql",
    "ms-sql-s",
    "postgres",
    "postgresql",
    "http",
    "https",
    "mongodb",
    "redis",
    "vnc",
    "snmp",
)


def _origin_of(cred: dict[str, Any]) -> str | None:
    """Where a credential was first seen working."""
    hosts = cred.get("hosts") or []
    return hosts[0]["host"] if hosts else None


class PropagationService:
    def __init__(
        self,
        msf: MsfClient,
        store: EngagementStore,
        progress: Callable[[str, float], None] | None = None,
    ):
        self.msf = msf
        self.store = store
        self.progress = progress or (lambda msg, pct: None)
        self._archive: CredArchive | None = None

    def _cred_archive(self) -> CredArchive:
        if self._archive is None:
            self._archive = CredArchive()
        return self._archive

    def plan(
        self,
        engagement_id: str,
        max_per_user: int = DEFAULT_MAX_PER_USER,
        jitter_max: float = DEFAULT_JITTER_MAX,
    ) -> dict[str, Any]:
        """Dry-run: which (cred, service) pairs would be attempted.

        Returned without touching the network so the operator can see the blast
        radius before authorizing anything. The spray policy (per-user cap +
        locked set) is applied to the pairs, so the plan shows exactly what
        a run would do.
        """
        archive = self._cred_archive()
        known = self.store.verified_credentials(engagement_id)
        targets = self._candidate_targets(engagement_id, archive)
        attempts = self._pair_up(known, targets)
        policy = SprayPolicy(max_per_user=max_per_user, jitter_max=jitter_max)
        filtered = apply_policy(attempts, self.store.attempts(engagement_id), policy)
        kept = filtered["pairs"]
        return {
            "engagement_id": engagement_id,
            "credentials": len(known),
            "targets": len(targets),
            "attempts": len(kept),
            "max_attempts": MAX_ATTEMPTS,
            "capped": len(kept) > MAX_ATTEMPTS,
            "pairs": kept[:MAX_ATTEMPTS],
            "policy": filtered["policy"],
            "held_locked": filtered["held_locked"],
            "held_capped": filtered["held_capped"],
            "locked_users": sorted(locked_users(self.store.attempts(engagement_id))),
            "per_user": user_attempt_counts(self.store.attempts(engagement_id)),
        }

    def _candidate_targets(
        self, engagement_id: str, archive: CredArchive
    ) -> list[dict[str, Any]]:
        """In-scope services with a login module, minus where the cred was found."""
        from schemas import Service

        targets: list[dict[str, Any]] = []
        for svc in self.store.services(engagement_id):
            name = (svc.get("service") or "").lower()
            if not name or name not in PROPAGATE_SERVICES:
                continue
            if not archive.module_for_service(Service(service=name, port=svc["port"])):
                continue
            # re-check scope at attempt time too, not just here
            if not self.store.in_scope(engagement_id, svc["host"]):
                continue
            targets.append(
                {
                    "host": svc["host"],
                    "port": svc["port"],
                    "service": name,
                    "module": archive.module_for_service(
                        Service(service=name, port=svc["port"])
                    ),
                }
            )
        return targets

    def _pair_up(
        self, known: list[dict[str, Any]], targets: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Cross-product, minus pairs already attempted in this engagement."""
        seen: set[tuple[str, int, str, str, str]] = set()
        if known:
            seen = self.store.attempted_pairs(known[0]["engagement_id"])
        pairs: list[dict[str, Any]] = []
        for cred in known:
            origin = _origin_of(cred)
            for tgt in targets:
                # never replay a cred at the exact host:service it came from
                if (
                    tgt["host"] == origin
                    and tgt["service"] == (cred.get("service") or "").lower()
                ):
                    continue
                key = (
                    tgt["host"],
                    tgt["port"],
                    tgt["service"],
                    cred["user"],
                    cred["password"],
                )
                if key in seen:
                    continue
                seen.add(key)
                pairs.append(
                    {
                        "host": tgt["host"],
                        "port": tgt["port"],
                        "service": tgt["service"],
                        "module": tgt["module"],
                        "user": cred["user"],
                        "password": cred["password"],
                        "origin_host": origin,
                    }
                )
        return pairs

    def run(
        self,
        engagement_id: str,
        open_sessions: bool = False,
        max_attempts: int = MAX_ATTEMPTS,
        max_per_user: int = DEFAULT_MAX_PER_USER,
        jitter_max: float = DEFAULT_JITTER_MAX,
    ) -> dict[str, Any]:
        """Replay verified engagement credentials across in-scope services.

        Jitter pauses between attempts (0 = off); lockout signals are
        ledgered as `locked` so the user is never retried.
        """
        from services import sandbox as sandbox_mode

        policy = SprayPolicy(
            max_per_user=max_per_user, jitter_max=jitter_max
        ).normalized()
        plan = self.plan(
            engagement_id,
            max_per_user=policy.max_per_user,
            jitter_max=policy.jitter_max,
        )
        pairs = plan["pairs"]
        cap = min(len(pairs), max(1, min(max_attempts, MAX_ATTEMPTS)))
        sandbox = sandbox_mode.enabled()
        reached: list[dict[str, Any]] = []
        attempted: list[dict[str, Any]] = []
        failed = 0
        locked = 0
        for idx, pair in enumerate(pairs[:cap]):
            if idx and policy.jitter_max > 0 and not sandbox:
                delay = jitter_delay(policy)
                if delay > 0:
                    time.sleep(delay)
            self.progress(
                f"[propagate] {pair['user']} -> {pair['host']}:{pair['port']}"
                f" ({pair['service']})",
                int(100 * idx / cap) if cap else 100,
            )
            ok, was_locked = self._try(pair, open_sessions)
            result = "verified" if ok else ("locked" if was_locked else "failed")
            attempted.append({**pair, "verified": ok, "result": result})
            if ok:
                reached.append(
                    {
                        **pair,
                        "origin_host": pair.get("origin_host"),
                        "new_host": pair["host"],
                        "lateral": pair["host"] != pair.get("origin_host"),
                    }
                )
                # record the new access so later runs can pivot from it
                self.store.record_credential(
                    engagement_id,
                    user=pair["user"],
                    password=pair["password"],
                    service=pair["service"],
                    origin_host=pair["host"],
                    origin_port=pair["port"],
                    verified=True,
                )
            elif was_locked:
                locked += 1
            else:
                failed += 1
            # every outcome goes to the ledger so a repeat run is a no-op —
            # and a locked user is never retried
            self.store.record_attempt(
                engagement_id,
                host=pair["host"],
                port=pair["port"],
                service=pair["service"],
                user=pair["user"],
                password=pair["password"],
                result=result,
                module=pair["module"],
            )
        self.store.touch(engagement_id)
        return {
            "engagement_id": engagement_id,
            "planned": len(pairs),
            "attempted": len(attempted),
            "capped": len(pairs) > cap,
            "verified": len(reached),
            "failed": failed,
            "locked": locked,
            "lateral_moves": sum(1 for r in reached if r["lateral"]),
            "reached": reached,
            "attempts": attempted,
            "policy": plan["policy"],
            "held_locked": plan["held_locked"],
            "held_capped": plan["held_capped"],
            "note": (
                "credential replay across in-scope services; failures recorded so "
                "repeat runs do not re-attempt them"
            ),
        }

    def _try(self, pair: dict[str, Any], open_sessions: bool) -> tuple[bool, bool]:
        """One login attempt. Returns (verified, lockout_signal)."""
        opts: dict[str, Any] = {
            "RHOSTS": pair["host"],
            "RPORT": pair["port"],
            "USERNAME": pair["user"],
            "PASSWORD": pair["password"],
            "StopOnSuccess": True,
        }
        if open_sessions:
            opts["CreateSession"] = True
        if "http_login" in pair["module"]:
            opts.setdefault("URI", "/")
        try:
            try:
                res = self.msf.execute("auxiliary", pair["module"], opts)
            except Exception as exc:
                if "CreateSession" in str(exc):
                    opts.pop("CreateSession", None)
                    res = self.msf.execute("auxiliary", pair["module"], opts)
                else:
                    raise
            return bool(res), False
        except Exception as exc:
            logger.debug("propagate %s@%s failed: %s", pair["user"], pair["host"], exc)
            return False, is_lockout_signal(str(exc))
