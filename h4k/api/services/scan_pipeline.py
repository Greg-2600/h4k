# Orchestrates a scan job: target normalization -> optional DNS recon ->
# db_nmap port scan -> fingerprint -> auxiliary vuln/enum scanners ->
# optional (opt-in) default-credential verification -> collect findings.
import ipaddress
import logging
import subprocess  # nosec B404 - required to drive msfconsole / bash recon tools
from collections.abc import Callable
from contextlib import suppress

from schemas import ScanRequest, Service
from services.creds import CredArchive
from services.modes import ScanModeConfig, get_mode, scanners_for_service
from services.msfrpc import MsfClient

logger = logging.getLogger("h4k.pipeline")


class _ScanAbort(Exception):
    """Raised when a scan is requested to stop mid-run."""


# Token hints used to fingerprint make/model/os/technology from banners.
VENDOR_HINTS: list[tuple[str, str]] = [
    # (vendor keyword, vendor name)
    ("linksys", "linksys"),
    ("cisco", "cisco"),
    ("netgear", "netgear"),
    ("tp-link", "tp-link"),
    ("tplink", "tp-link"),
    ("tenda", "tenda"),
    ("d-link", "dlink"),
    ("dlink", "dlink"),
    ("belkin", "belkin"),
    ("draytek", "draytek"),
    ("vigor", "draytek"),
    ("asuswrt", "asus"),
    ("asus", "asus"),
    ("zyxel", "zyxel"),
    ("mikrotik", "mikrotik"),
    ("routeros", "mikrotik"),
    ("ubiquiti", "ubiquiti"),
    ("unifi", "ubiquiti"),
    ("airmax", "ubiquiti"),
    ("arris", "arris"),
    ("motorola", "motorola"),
    ("surfboard", "arris"),
    ("synology", "synology"),
    ("diskstation", "synology"),
    ("qnap", "qnap"),
    ("raspberry", "raspberry-pi"),
    ("raspbian", "raspberry-pi"),
    ("openwrt", "openwrt"),
    ("lede", "openwrt"),
    ("pfsense", "pfsense"),
    ("opnsense", "pfsense"),
    ("hikvision", "hikvision"),
    ("dahua", "dahua"),
    ("axis", "axis"),
    ("brother", "brother"),
    ("hp ", "hp"),
    ("kyocera", "kyocera"),
    ("epson", "epson"),
    ("ricoh", "ricoh"),
]

OS_HINTS: list[tuple[str, str]] = [
    ("windows", "windows"),
    ("microsoft windows", "windows"),
    ("mac os", "macos"),
    ("macos", "macos"),
    ("darwin", "macos"),
    ("ubuntu", "linux"),
    ("debian", "linux"),
    ("fedora", "linux"),
    ("red hat", "linux"),
    ("centos", "linux"),
    ("linux", "linux"),
]

# Web technologies to look for in http banners / whatweb output
TECH_HINTS: list[tuple[str, str]] = [
    ("apache", "apache"),
    ("nginx", "nginx"),
    ("iis", "iis"),
    ("lighttpd", "lighttpd"),
    ("cherrypy", "cherrypy"),
    ("php", "php"),
    ("tomcat", "tomcat"),
    ("jetty", "jetty"),
    ("nginx", "nginx"),
    ("openwrt", "openwrt"),
]


class ScanPipeline:
    def __init__(
        self,
        msf: MsfClient,
        progress: Callable[[str, float], None] | None = None,
        log: Callable[[str], None] | None = None,
        should_stop: Callable[[], bool] | None = None,
    ):
        self.msf = msf
        self.progress = progress or (lambda msg, pct: None)
        self._log = log or (lambda msg: None)
        self._should_stop = should_stop or (lambda: False)

    # ---- helpers -----------------------------------------------------------

    def _tick(self, message: str, pct: float) -> None:
        logger.info("%s (%.0f%%)", message, pct)
        self._log(message)
        self.progress(message, pct)

    def _check_abort(self) -> bool:
        """Return True and log if the run has been requested to stop."""
        if self._should_stop():
            logger.info("abort requested mid-scan")
            self._log("abort requested — stopping scan")
            return True
        return False

    @staticmethod
    def normalize_target(target: str) -> str:
        # Accept bare IP, IP/CIDR, or a hostname; Metasploit RHOSTS/RHNOSTS
        # understands these directly. Single IPs get /32 for range scan clarity.
        try:
            ip = ipaddress.ip_address(target)
            return str(ip)
        except ValueError:
            if "/" in target:
                try:
                    ipaddress.ip_network(target, strict=False)
                    return target
                except ValueError:
                    pass
            return target  # domain name

    # ---- public API --------------------------------------------------------

    def run(self, req: ScanRequest) -> dict:
        mode = get_mode(req.mode.value)
        target = self.normalize_target(req.target)
        self._tick(f"[{mode.name}] normalized target -> {target}", 5)

        # 1. Optional DNS recon enrichment (your GitHub bash tools).
        dns_notes: list[str] = []
        if req.do_dns_recon and _looks_like_domain(req.target):
            self._raises_if_aborted()
            dns_notes = self._dns_recon(req.target)
            self._tick("DNS recon complete", 15)

        self._raises_if_aborted()

        # 2. Port scan into the DB.
        self._tick("starting port scan (db_nmap)", 20)
        self._db_nmap(target, mode.nmap_args)
        self._raises_if_aborted()

        # 3. Pull hosts + services from DB.
        hosts = self._collect_hosts_and_services(target)

        # 4. Reverse-DNS (PTR) lookups for every discovered IP.
        self._tick("reverse DNS (PTR) lookups", 28)
        try:
            dns_notes += self._reverse_dns([h["address"] for h in hosts])
        except Exception as exc:
            logger.debug("reverse dns failed: %s", exc)

        # 5. Fingerprint make/model/os/technology from banners + whatweb.
        self._tick("fingerprinting hosts", 35)
        fingerprints = self._fingerprint(hosts, mode)
        self._raises_if_aborted()

        # 5. Run auxiliary scanners per detected service.
        self._tick("running auxiliary vuln/enum scanners", 45)
        self._run_aux_scanners(hosts, mode)
        self._raises_if_aborted()

        # 6. Collect vulnerabilities.
        vulns = self._collect_vulns(target)
        self._tick("collecting vulnerability findings", 80)
        self._raises_if_aborted()

        # 7. OPT-IN: try default/known credentials against matched services.
        credentials: list[dict] = []
        if req.try_default_creds:
            self._tick("attempting default credential verification (opt-in)", 88)
            credentials = self._try_default_creds(
                hosts, fingerprints, req.open_sessions
            )
            self._raises_if_aborted()

        # 8. OPT-IN: attempt active exploitation.
        attacks: list[dict] = []
        if req.do_attack:
            self._tick("attempting active exploitation (opt-in)", 92)
            attacks = self._do_attacks(hosts, req.open_sessions)

        # 9. Metasploit's own "analyze" suggestions.
        self._tick("running module analysis recommendations", 96)
        notes = dns_notes + self._analyze(target)

        report = {
            "target": req.target,
            "mode": req.mode.value,
            "hosts": hosts,
            "vulns": vulns,
            "notes": list(set(notes)),
            "fingerprints": fingerprints,
            "credentials": credentials,
            "attacks": attacks,
        }
        self._tick("scan complete", 100)
        return report

    def _raises_if_aborted(self) -> None:
        if self._should_stop():
            self._log("abort requested — stopping scan")
            raise _ScanAbort()

    def _do_attacks(self, hosts: list[dict], open_sessions: bool) -> list[dict]:
        """Opt-in exploitation: run exploit modules against discovered services."""
        from services.attack import AttackService

        svc = AttackService(self.msf, progress=self._tick)
        # Build an AttackRequest-style list of services per host.
        attacks: list[dict] = []
        for host in hosts:
            addr = host["address"]
            for s in host["services"]:
                sname = s.get("service") or ""
                module = AttackService._module_for_service(sname)
                if not module:
                    continue
                self._log(f"[attack] {addr} {sname} -> {module}")
                res = svc._try_exploit(module, addr, sname, open_sessions)
                attacks.append(
                    {
                        "host": addr,
                        "service": sname,
                        "port": s.get("port"),
                        "module": module,
                        "result": "success" if res["ok"] else "failed",
                        "detail": res["detail"],
                        "session_id": res.get("session_id"),
                    }
                )
        return attacks

    # ---- steps -------------------------------------------------------------

    def _db_nmap(self, target: str, args: list[str]) -> None:
        with suppress(ValueError):
            target = str(ipaddress.ip_address(target))
        # db_nmap writes host/service/vuln rows straight into the Metasploit DB
        # (reuses the framework's nmap + import path rather than reimplementing).
        cmd = ["db_nmap", *args, target]
        self._msfconsole_run(cmd)

    def _msfconsole_run(self, argv: list[str]) -> str:
        # The DB is already connected by msfrpcd, so just run db_nmap.
        # argv is built internally from fixed module names (not user input).
        cmd_str = " ".join(argv)
        cli = f"msfconsole -q -x '{cmd_str};' </dev/null"
        proc = subprocess.run(  # nosec B603 B607 - internal argv, bash required
            ["bash", "-lc", cli],
            capture_output=True,
            text=True,
            timeout=3600,
            check=False,
        )
        return proc.stdout + proc.stderr

    def _collect_hosts_and_services(self, target: str) -> list:
        hosts = []
        ws = self.msf.current_workspace() or "default"
        try:
            for rec in self.msf.hosts(ws):
                addr = rec.get("address")
                if addr is None:
                    continue
                if not _target_matches(addr, target):
                    continue
                hosts.append(
                    {
                        "address": addr,
                        "hostname": rec.get("name") or None,
                        "os": rec.get("os_name") or rec.get("os_flavor") or None,
                        "state": rec.get("state"),
                        "services": [],
                    }
                )
        except Exception as exc:
            logger.warning("hosts() failed: %s", exc)

        try:
            for rec in self.msf.services(ws):
                addr = rec.get("host") or rec.get("host_id")
                if not _target_matches(str(addr), target):
                    continue
                for host in hosts:
                    if host["address"] == str(addr):
                        host["services"].append(
                            {
                                "port": rec.get("port"),
                                "proto": rec.get("proto"),
                                "service": rec.get("name"),
                                "state": rec.get("state"),
                                "info": rec.get("info"),
                            }
                        )
        except Exception as exc:
            logger.warning("services() failed: %s", exc)
        return hosts

    def _run_aux_scanners(
        self, hosts: list[dict], mode: ScanModeConfig, timeout: float = 200.0
    ) -> None:
        import time

        launched: list[tuple[object, str, str]] = []  # job_id, module, uuid
        for host in hosts:
            addr = host["address"]
            for svc in host["services"]:
                for module in scanners_for_service(svc.get("service") or ""):
                    opts: dict[str, object] = {"RHOSTS": addr}
                    if svc.get("port"):
                        opts["RPORT"] = svc["port"]
                    if mode.proxies:
                        opts["Proxies"] = mode.proxies
                    try:
                        self._log(f"[scan] {module} {addr}")
                        res = self.msf.execute("auxiliary", module, opts)
                        if isinstance(res, dict) and res.get("job_id") is not None:
                            launched.append(
                                (res["job_id"], module, str(res.get("uuid", "")))
                            )
                        logger.info("launched %s (job %s)", module, res.get("job_id"))
                    except Exception as exc:
                        logger.warning("aux scanner %s failed: %s", module, exc)

        # Wait briefly for launched scanner jobs to complete so their findings
        # are written to the DB before we collect vulns.
        if not launched:
            return
        deadline = time.time() + timeout
        while time.time() < deadline:
            pending = False
            try:
                running = self.msf.jobs()
            except Exception:
                running = {}
            for job_id, _mod, _uuid in launched:
                if str(job_id) in running:
                    pending = True
            if not pending:
                logger.info("all %d scanner job(s) finished", len(launched))
                break
            time.sleep(3)

    def _collect_vulns(self, target: str) -> list:
        vulns = []
        ws = self.msf.current_workspace() or "default"
        try:
            for rec in self.msf.vulns(ws):
                addr = rec.get("host")
                if not _target_matches(str(addr), target):
                    continue
                vulns.append(
                    {
                        "name": rec.get("name") or rec.get("info") or "unknown",
                        "refs": rec.get("refs") or [],
                        "port": rec.get("port"),
                        "info": rec.get("info"),
                    }
                )
        except Exception as exc:
            logger.warning("vulns() failed: %s", exc)
        return vulns

    def _analyze(self, target: str) -> list:
        notes = []
        ws = self.msf.current_workspace() or "default"
        for host in self._target_ips(target):
            try:
                res = self.msf.analyze_host(host, ws)
                # res is {"host": {"address": ..., "modules": [...]}}
                host_info = res.get("host", {}) if isinstance(res, dict) else {}
                modules = host_info.get("modules") or []
                if modules:
                    names = ", ".join(str(m) for m in modules[:8])
                    notes.append(f"Metasploit analyze@{host} suggests: {names}")
                else:
                    notes.append(f"Metasploit analyze@{host}: 0 module suggestions")
            except Exception as exc:
                logger.warning("analyze failed for %s: %s", host, exc)
        return notes

    def _target_ips(self, target: str) -> list:
        try:
            net = ipaddress.ip_network(target, strict=False)
            return [str(x) for x in net.hosts()][:256]
        except ValueError:
            try:
                return [str(ipaddress.ip_address(target))]
            except ValueError:
                return [target]

    # ---- fingerprinting -----------------------------------------------------

    def _fingerprint(self, hosts: list[dict], mode: ScanModeConfig) -> list[dict]:
        """Best-effort make/model/os/tech identification from nmap banners and
        (for web services) whatweb output. Never definitive, always a hint."""
        results: list[dict] = []
        for host in hosts:
            addr = host["address"]
            text_pool = [
                host.get("os") or "",
                *(svc.get("info") or "" for svc in host["services"]),
                *(svc.get("service") or "" for svc in host["services"]),
            ]
            text = " ".join(text_pool)
            vendor = _match_hints(text, VENDOR_HINTS)
            os_guess = _match_hints(text, OS_HINTS)
            tech = _match_hints_many(text, TECH_HINTS)
            source = ["nmap-banner"]

            # whatweb gives much better web tech fingerprinting.
            if mode.name != "tor":
                www = self._whatweb(addr)
                if www:
                    source.append("whatweb")
                    text = " ".join([text, www])
                    vendor2 = _match_hints(text, VENDOR_HINTS)
                    if vendor2:
                        vendor = vendor2 or vendor
                    tech = list(
                        dict.fromkeys(tech + _match_hints_many(text, TECH_HINTS))
                    )

            results.append(
                {
                    "host": addr,
                    "vendor": vendor,
                    "model": None,
                    "os": os_guess or host.get("os"),
                    "technology": tech,
                    "source": sorted(set(source)),
                }
            )
        return results

    def _whatweb(self, addr: str) -> str:
        """Run whatweb (if present) for web tech fingerprinting. Returns plain text."""
        try:
            proc = subprocess.run(  # nosec B603 B607 - fixed binary, no shell
                ["whatweb", "--no-errors", "--color=never", "-a", "3", addr],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            return (proc.stdout or proc.stderr).strip()
        except FileNotFoundError:
            logger.debug("whatweb not installed; skipping web fingerprint")
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("whatweb failed for %s: %s", addr, exc)
        return ""

    # ---- opt-in default credential verification -----------------------------

    def _try_default_creds(
        self,
        hosts: list[dict],
        fingerprints: list[dict],
        open_sessions: bool,
    ) -> list[dict]:
        """Opt-in: try default/known credentials from the archive against
        services that carry a login module. Returns verified credentials for
        the report. Only runs for authorized lab targets, and only when the
        requesting scan turned `try_default_creds` on."""
        try:
            archive = CredArchive()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("could not load cred archive: %s", exc)
            return []

        found: list[dict] = []
        vendor_map = {f["host"]: f for f in fingerprints}
        for host in hosts:
            addr = host["address"]
            fp = vendor_map.get(addr, {})
            vendor_creds = archive.match_fingerprints(
                [fp.get("vendor") or "", *(fp.get("technology") or [])]
            )
            for svc in host["services"]:
                svc_model = _service_from_dict(svc)
                module = archive.module_for_service(svc_model)
                if not module:
                    continue
                candidates = archive.vendor_for_service(
                    vendor_creds, svc_model
                ) + archive.universal_for_service(svc_model)
                # dedupe identical (user,pass) across vendor+universal
                seen_pr = set()
                _BLANK = "blank"  # sentinel for blank-cred marker  # nosec B105
                for cred in candidates:
                    user = str(cred.get("user") or "").strip("()")
                    password = str(cred.get("pass") or "").strip("()")
                    if user == _BLANK or password == _BLANK or not user:  # nosec B105
                        continue  # skip blank-cred fallbacks in automation
                    if (user, password) in seen_pr:
                        continue
                    seen_pr.add((user, password))
                    res = self._try_one(
                        module, addr, svc, user, password, open_sessions
                    )
                    found.append(
                        {
                            "vendor": _cred_vendor(fp, vendor_creds, cred),
                            "service": svc.get("service") or svc["port"],
                            "host": addr,
                            "port": svc.get("port"),
                            "user": user,
                            "password": password,
                            "module": module,
                            "verified": bool(res),
                            "note": cred.get("desc") or "",
                        }
                    )
        return found

    def _try_one(
        self,
        module: str,
        addr: str,
        svc: dict,
        user: str,
        password: str,
        open_sessions: bool,
    ) -> bool:
        port = svc.get("port")
        opts: dict[str, object] = {
            "RHOSTS": addr,
            "RPORT": port,
            "USERNAME": user,
            "PASSWORD": password,
            "StopOnSuccess": True,
        }
        if open_sessions:
            opts["CreateSession"] = True
        # http_login requires a web path to POST to; default to /.
        if "http_login" in module:
            opts.setdefault("URI", "/")
        self._log(f"[creds] try {user}:{password} on {addr}:{port} ({module})")
        try:
            try:
                res = self.msf.execute("auxiliary", module, opts)
            except Exception as exc:
                # retry without CreateSession if a module rejects it
                if "CreateSession" in str(exc):
                    opts.pop("CreateSession", None)
                    res = self.msf.execute("auxiliary", module, opts)
                else:
                    raise
            ok = bool(res)
            self._log(
                f"[creds] {'VERIFIED' if ok else 'no match'} "
                f"{user}:{password} on {addr}"
            )
            return ok
        except Exception as exc:
            logger.debug("cred %s:%s on %s failed: %s", user, password, addr, exc)
            self._log(f"[creds] error {user} {password} @ {addr}: {exc}")
            return False

    # ---- DNS recon via Greg's bash tools -----------------------------------

    def _dns_recon(self, domain: str) -> list:
        """DNS footprinting for a domain: dig records, subdomain enum, and
        dnstracer/traceroute for path/authority mapping (all best-effort)."""
        notes = []
        tool_map = {
            "dns_dumpster.sh": ["dns_dumpster.sh", domain],
            "sub_domain_lookup.sh": ["sub_domain_lookup.sh", domain],
        }
        for name, argv in tool_map.items():
            try:
                # argv[0] is a fixed script path; domain is passed as a bare
                # argument (no shell interpolation), safe from injection.
                proc = subprocess.run(  # nosec B603 - no shell, fixed script
                    argv,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    cwd="/opt/h4k/scripts",
                    check=False,
                )
                if proc.stdout.strip():
                    notes.append(f"[{name}] {proc.stdout.strip()[:300]}")
            except Exception as exc:
                logger.warning("dns tool %s failed: %s", name, exc)

        # dig records (A/AAAA/MX/NS/TXT) via the bundled bash tools' output
        notes.extend(
            self._run_shell_tool("dig_any", ["dig", "+noall", "+answer", domain])
        )
        # trace the authoritative path / network route
        notes.extend(self._run_shell_tool("dnstracer", ["dnstracer", domain]))
        notes.extend(
            self._run_shell_tool("traceroute", ["traceroute", "-m", "15", domain])
        )
        return notes

    def _run_shell_tool(self, name: str, argv: list[str]) -> list:
        """Run a recon shell tool best-effort and return capped notes."""
        try:
            proc = subprocess.run(  # nosec B603 - bare argv, no shell
                argv, capture_output=True, text=True, timeout=120, check=False
            )
            out = (proc.stdout or proc.stderr or "").strip()
            if out:
                return [f"[{name}] {out[:300]}"]
        except FileNotFoundError:
            logger.debug("%s not installed; skipping", name)
        except Exception as exc:
            logger.warning("%s failed: %s", name, exc)
        return []

    def _reverse_dns(self, ips: list[str]) -> list:
        """PTR lookups for discovered IPs using dig (best-effort)."""
        notes: list[str] = []
        seen = set()
        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)
            names = self._reverse_dns_one(ip)
            if names:
                notes.append(f"[ptr] {ip} -> {', '.join(names[:3])}")
        return notes

    @staticmethod
    def _reverse_dns_resolvers() -> list[str]:
        return ["8.8.8.8", "9.9.9.9", "1.1.1.1"]

    @classmethod
    def _reverse_dns_one(cls, ip: str) -> list[str]:
        """PTR lookup for one IP via dig, with public-resolver fallback."""
        last_err: Exception | None = None
        for resolver in cls._reverse_dns_resolvers():
            try:
                proc = subprocess.run(  # nosec B603 B607 - bare argv
                    ["dig", "@" + resolver, "+short", "-x", ip],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                )
                out = (proc.stdout or "").strip().splitlines()
                # filter out resolution errors like 'REFUSED' or 'not found'
                names = [
                    ln for ln in out if "." in ln and "not found" not in ln.lower()
                ]
                if names:
                    return names
            except FileNotFoundError:
                logger.debug("dig not installed; skipping PTR")
                return []
            except Exception as exc:
                last_err = exc
                logger.debug("PTR %s via %s failed: %s", ip, resolver, exc)
        if last_err:
            return []  # all resolvers failed
        return []


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _looks_like_domain(value: str) -> bool:
    if "/" in value or _is_ip(value):
        return False
    return "." in value


def _target_matches(addr: str | None, target: str) -> bool:
    if not addr:
        return False
    try:
        net = ipaddress.ip_network(target, strict=False)
        return ipaddress.ip_address(addr) in net
    except ValueError:
        return addr == target


def _match_hints(
    text: str, hints: list[tuple[str, str]], all_matches: bool = False
) -> str | list[str]:
    """Return the first matched label (or all labels) from hint tokens."""
    if all_matches:
        return _match_hints_many(text, hints)
    lowered = text.lower()
    for token, label in hints:
        if token in lowered:
            return label
    return ""


def _match_hints_many(text: str, hints: list[tuple[str, str]]) -> list[str]:
    """Return every matching hint label as a list."""
    lowered = text.lower()
    hits = [label for token, label in hints if token in lowered]
    return list(dict.fromkeys(hits))


def _cred_vendor(fp: dict, vendor_creds: list[dict], cred: dict) -> str:
    """Best-effort vendor label for a credential (fingerprint or archive)."""
    if fp.get("vendor"):
        return fp["vendor"]
    return cred.get("vendor") or "common"


def _service_from_dict(s: dict) -> Service:
    """Build a schemas.Service from a raw host-services dict."""
    return Service(
        port=s.get("port"),
        proto=s.get("proto", "tcp"),
        service=s.get("service"),
        state=s.get("state"),
        info=s.get("info"),
    )
