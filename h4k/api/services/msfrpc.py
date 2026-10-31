# Thin wrapper around pymetasploit3 -> msfrpcd (MessagePack RPC, port 55553).
import logging
import time

from pymetasploit3.msfrpc import MsfRpcClient

logger = logging.getLogger("h4k.msfrpc")

RETRY_ATTEMPTS = 10
RETRY_SLEEP = 2.0

# pymetasploit3 exposes the module catalogue as one attribute per type.
_MODULE_ATTRS = {
    "exploit": "exploits",
    "auxiliary": "auxiliary",
    "post": "post",
    "payload": "payloads",
    "encoder": "encoders",
    "evasion": "evasion",
    "nop": "nops",
}


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
        # PAYLOAD/LHOST/LPORT are payload-datastore keys, not module options:
        # assigning them on the module object raises "Invalid option", so
        # they go through the raw RPC where msfrpcd accepts them as datastore.
        if any(k in opts for k in ("PAYLOAD", "LHOST", "LPORT")):
            try:
                return _to_dict(
                    self.client.call("module.execute", [mtype, mname, opts])
                )
            except Exception as exc:
                logger.warning("module %s execute failed: %s", mname, exc)
                return {"error": str(exc), "status": "failed"}
        client = self.client
        try:
            mod = client.modules.use(mtype, mname)
        except Exception as exc:
            # pymetasploit3 crashes building some module objects: an MSF RPC
            # response carries a bool where it expects a {'required': ...}
            # dict, and ExploitModule.__init__ subscripts it. Surface that as
            # an honest structured error instead of unwinding the caller.
            logger.warning("module %s use failed: %s", mname, exc)
            return {"error": str(exc), "status": "failed"}
        for key, val in opts.items():
            mod[key] = val
        try:
            res = mod.execute()
            return _to_dict(res)
        except Exception as exc:
            # same class of pymetasploit3 brittleness: result['job_id'] on a
            # bool payload for a failed launch
            logger.warning("module %s execute failed: %s", mname, exc)
            return {"error": str(exc), "status": "failed"}

    def module_options(self, mtype: str, mname: str) -> set[str]:
        """Option names for a module, read straight from the RPC.

        pymetasploit3's ModuleManager.use() parses module.options with
        `self._moptions[o]['required']`, which explodes when the RPC answers
        with an error dict instead of the option map. Reading the RPC
        directly keeps the failure honest instead of turning it into a
        TypeError -- and it works for auxiliary/post modules too.
        """
        try:
            raw = self.client.call("module.options", [mtype, mname])
        except Exception as exc:
            logger.warning("could not read options for %s: %s", mname, exc)
            return set()
        if not isinstance(raw, dict) or raw.get("error"):
            return set()
        return set(raw.keys())

    def execute_module(self, mtype: str, mname: str, opts: dict) -> dict:
        """Run a module of any type (exploit / auxiliary / post).

        pymetasploit3's module objects are the happy path, but they break on
        auxiliary/post modules in current Metasploit builds. The plain RPC
        call is the fallback, so a scanner module still runs.

        Payload selection (PAYLOAD/LHOST/LPORT) always goes through the raw
        RPC: those are payload-datastore keys, not module options, so
        assigning them on the module object raises "Invalid option". msfrpcd
        accepts them as datastore in module.execute.
        """
        if any(k in opts for k in ("PAYLOAD", "LHOST", "LPORT")):
            try:
                return _to_dict(
                    self.client.call("module.execute", [mtype, mname, opts])
                )
            except Exception as exc:
                logger.warning("module %s execute failed: %s", mname, exc)
                return {"error": str(exc), "status": "failed"}
        try:
            mod = self.client.modules.use(mtype, mname)
            for key, val in opts.items():
                mod[key] = val
            return _to_dict(mod.execute())
        except Exception as exc:
            logger.warning("module %s use failed: %s", mname, exc)
        try:
            return _to_dict(self.client.call("module.execute", [mtype, mname, opts]))
        except Exception as exc:
            logger.warning("module %s execute failed: %s", mname, exc)
            return {"error": str(exc), "status": "failed"}

    def check(self, mtype: str, mname: str, opts: dict) -> dict:
        """Run a module's check (no exploitation).

        NOTE: never `mod.check()` here. pymetasploit3's Module.__init__ copies
        every info key onto the instance, and msf reports `check: true/false`
        in module info — so the `check()` method is shadowed by a bool
        ("'bool' object is not callable"). The raw `module.check` RPC has no
        such problem.

        Like execute, check runs as a job: the RPC answers
        {"job_id": N, "uuid": ...} and the verdict arrives later via
        module.results(uuid). Poll for it instead of reporting the job dict.
        """
        import time as _time

        try:
            started = self.client.call("module.check", [mtype, mname, dict(opts)])
        except Exception as exc:
            logger.warning("module %s check failed: %s", mname, exc)
            return {"error": str(exc), "status": "failed"}
        if not isinstance(started, dict) or not started.get("uuid"):
            return _to_dict(started)
        uuid = started["uuid"]
        deadline = _time.monotonic() + 90.0
        last: dict = {}
        _time.sleep(3)  # let the check job start before first poll
        while _time.monotonic() < deadline:
            try:
                last = self.client.call("module.results", [uuid]) or {}
            except Exception as exc:
                logger.warning("module %s results failed: %s", mname, exc)
                break
            if not isinstance(last, dict):
                break
            # the verdict nests under result: {status, result: {code, message}}
            inner = last.get("result")
            inner = inner if isinstance(inner, dict) else {}
            if inner.get("code") or inner.get("message"):
                break
            if last.get("code") or last.get("message"):
                break
            _time.sleep(3)
        return _to_dict(last) if last else _to_dict(started)

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
        """List all available modules of a given type (exploit/auxiliary/post).

        pymetasploit3 exposes the catalogue as one attribute per type
        (`modules.exploits`, `modules.auxiliary`, ...). Older builds used a
        `module_types` dict instead -- support both, because a silent empty
        list here means "no exploits found" on a perfectly good Metasploit.
        """
        try:
            mods = self.client.modules
            attr = _MODULE_ATTRS.get(mtype)
            if attr:
                names = getattr(mods, attr, None)
                if names:
                    return list(names)
            types = getattr(mods, "module_types", None)
            if types and mtype in types:
                return list(types[mtype])
        except Exception as exc:
            logger.warning("could not list modules: %s", exc)
        return []

    def get_module_info(self, mtype: str, mname: str) -> dict:
        """Get detailed info about a module (name, description, options)."""
        try:
            mod = self.client.modules.use(mtype, mname)
            raw_options = getattr(mod, "options", None)
            if isinstance(raw_options, dict):
                option_names = [str(k) for k in raw_options]
            elif isinstance(raw_options, (list, tuple)):
                option_names = [str(o) for o in raw_options]
            else:
                option_names = []
            return {
                "name": getattr(mod, "name", mname),
                "description": getattr(mod, "description", "") or "",
                "options": option_names,
                "mtype": mtype,
                "fullname": mname,
            }
        except Exception as exc:
            logger.warning("could not get module info for %s: %s", mname, exc)
            return {}

    def find_exploits(
        self, service: str | None = None, port: int | None = None
    ) -> list[dict]:
        """Find exploits matching a service or port.

        Matching happens on the module *name* first: fetching the metadata of
        all ~2700 exploits would mean thousands of RPC round-trips.
        """
        exploits: list[dict] = []
        try:
            names = self.list_modules("exploit")
        except Exception as exc:
            logger.warning("could not find exploits: %s", exc)
            return exploits
        for mname in names:
            if service:
                svc_lower = service.lower()
                if svc_lower not in mname.lower():
                    continue
            mod_info = self.get_module_info("exploit", mname)
            if not mod_info:
                continue
            if port is not None:
                mod_info["port"] = port
            exploits.append(mod_info)
        return exploits


def _to_dict(raw: object) -> dict:
    if isinstance(raw, dict):
        return raw
    return {}
