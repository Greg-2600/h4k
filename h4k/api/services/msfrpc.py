# Thin wrapper around pymetasploit3 -> msfrpcd (MessagePack RPC, port 55553).
import logging
import time

from pymetasploit3.msfrpc import MsfRpcClient

logger = logging.getLogger("h4k.msfrpc")

RETRY_ATTEMPTS = 10
RETRY_SLEEP = 2.0


class MsfClient:
    """Lazy, retrying connection wrapper for the local msfrpcd daemon."""

    def __init__(self, host: str, port: int, password: str):
        self.host = host
        self.port = port
        self.password = password
        self._client: MsfRpcClient | None = None

    def _connect(self) -> MsfRpcClient:
        if self._client is not None:
            try:
                # touch the connection to check it is still alive
                _ = self._client.core.version
                return self._client
            except Exception:
                self._client = None

        for attempt in range(1, RETRY_ATTEMPTS + 1):
            try:
                client = MsfRpcClient(
                    self.password,
                    server=self.host,
                    port=self.port,
                    # msfrpcd is started with -S true (SSL disabled); see entrypoint.
                    ssl=False,
                )
                logger.info("connected to msfrpcd @ %s:%s", self.host, self.port)
                self._client = client
                return client
            except Exception as exc:
                logger.warning(
                    "msfrpcd connect attempt %s/%s failed: %s",
                    attempt,
                    RETRY_ATTEMPTS,
                    exc,
                )
                time.sleep(RETRY_SLEEP)
        raise ConnectionError("could not reach msfrpcd")

    @property
    def client(self) -> MsfRpcClient:
        return self._connect()

    # ---- module wrappers ---------------------------------------------------

    def execute(self, mtype: str, mname: str, opts: dict) -> dict:
        client = self.client
        mod = client.modules.use(mtype, mname)
        for key, val in opts.items():
            mod[key] = val
        res = mod.execute()
        return _to_dict(res)

    def check(self, mtype: str, mname: str, opts: dict) -> dict:
        client = self.client
        mod = client.modules.use(mtype, mname)
        for key, val in opts.items():
            mod[key] = val
        res = mod.check()
        return _to_dict(res)

    # ---- db wrappers -------------------------------------------------------
    # pymetasploit3's DbManager only exposes connect/driver/status/workspace,
    # so call the DB RPC methods directly with the workspace filter.

    def _db_call(self, method: str, workspace: str = "default", **filt: object) -> list:
        opts: dict[str, object] = dict(filt)
        opts["workspace"] = workspace
        res = self.client.call(method, [opts])
        if not isinstance(res, dict):
            return []
        key = method.rsplit(".", 1)[-1]
        if key not in res:
            return []
        val = res[key]
        return val if isinstance(val, list) else [val]

    def hosts(self, workspace: str = "default") -> list:
        return self._db_call("db.hosts", workspace)

    def services(self, workspace: str = "default") -> list:
        return self._db_call("db.services", workspace)

    def vulns(self, workspace: str = "default") -> list:
        return self._db_call("db.vulns", workspace)

    def current_workspace(self) -> str:
        return self.client.db.workspace

    def report_host(self, address: str, **kwargs: object) -> dict:
        opts: dict[str, object] = {
            "address": address,
            "workspace": self.current_workspace(),
        }
        opts.update(kwargs)
        return _to_dict(self.client.call("db.report_host", [opts]))

    def analyze_host(self, ip: str, workspace: str = "default") -> dict:
        opts = {"host": ip, "workspace": workspace}
        return _to_dict(self.client.call("db.analyze_host", [opts]))

    # ---- sessions / jobs ---------------------------------------------------

    def sessions(self) -> dict:
        return _to_dict(self.client.sessions.list)

    def jobs(self) -> dict:
        return _to_dict(self.client.jobs.list)

    def module_results(self, uuid: str) -> dict:
        return _to_dict(self.client.modules.results(uuid))

    def list_modules(self, mtype: str) -> list[str]:
        """List all available modules of a given type (exploit/auxiliary/post)."""
        try:
            mods = self.client.modules.module_types
            if mtype in mods:
                return list(mods[mtype])
        except Exception as exc:
            logger.warning("could not list modules: %s", exc)
        return []

    def get_module_info(self, mtype: str, mname: str) -> dict:
        """Get detailed info about a module (name, description, options)."""
        try:
            mod = self.client.modules.use(mtype, mname)
            return {
                "name": getattr(mod, "name", mname),
                "description": getattr(mod, "description", ""),
                "options": (
                    list(getattr(mod, "options", {}).keys())
                    if hasattr(mod, "options")
                    else []
                ),
                "mtype": mtype,
                "fullname": mname,
            }
        except Exception as exc:
            logger.warning("could not get module info for %s: %s", mname, exc)
            return {}

    def find_exploits(
        self, service: str | None = None, port: int | None = None
    ) -> list[dict]:
        """Find exploits matching a service or port."""
        exploits = []
        try:
            for mname in self.list_modules("exploit"):
                mod_info = self.get_module_info("exploit", mname)
                if not mod_info:
                    continue
                # Simple relevance matching
                if service:
                    svc_lower = service.lower()
                    mod_desc = mod_info.get("description", "").lower()
                    mod_name = mname.lower()
                    if svc_lower in mod_name or svc_lower in mod_desc:
                        exploits.append(mod_info)
                elif port:
                    mod_info["port"] = port
                    exploits.append(mod_info)
        except Exception as exc:
            logger.warning("could not find exploits: %s", exc)
        return exploits


def _to_dict(raw: object) -> dict:
    if isinstance(raw, dict):
        return raw
    return {}
