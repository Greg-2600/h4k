# Orchestrates a scan job: target normalization -> optional DNS recon ->
# db_nmap port scan -> auxiliary vuln/enum scanners -> collect findings.
import ipaddress
import logging
import subprocess
from typing import Callable, List, Optional

from schemas import ScanMode, ScanRequest

from services.modes import get_mode, scanners_for_service
from services.msfrpc import MsfClient

logger = logging.getLogger("h4k.pipeline")


class ScanPipeline:
    def __init__(
        self,
        msf: MsfClient,
        progress: Optional[Callable[[str, float], None]] = None,
    ):
        self.msf = msf
        self.progress = progress or (lambda msg, pct: None)

    # ---- helpers -----------------------------------------------------------

    def _tick(self, message: str, pct: float):
        logger.info("%s (%.0f%%)", message, pct)
        self.progress(message, pct)

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

    def run(self, req: ScanRequest, job_id: str) -> dict:
        mode = get_mode(req.mode.value)
        target = self.normalize_target(req.target)
        self._tick(f"[{mode.name}] normalized target -> {target}", 5)

        # 1. Optional DNS recon enrichment (your GitHub bash tools).
        dns_notes: List[str] = []
        if req.do_dns_recon and _looks_like_domain(req.target):
            dns_notes = self._dns_recon(req.target)
            self._tick("DNS recon complete", 15)

        # 2. Port scan into the DB.
        self._tick("starting port scan (db_nmap)", 20)
        self._db_nmap(target, mode.nmap_args)

        # 3. Pull hosts + services from DB.
        hosts = self._collect_hosts_and_services(target)

        # 4. Run auxiliary scanners per detected service.
        self._tick("running auxiliary vuln/enum scanners", 45)
        self._run_aux_scanners(hosts, mode)

        # 5. Collect vulnerabilities.
        vulns = self._collect_vulns(target)
        self._tick("collecting vulnerability findings", 85)

        # 6. Metasploit's own "analyze" suggestions.
        self._tick("running module analysis recommendations", 90)
        notes = dns_notes + self._analyze(target)

        report = {
            "target": req.target,
            "mode": req.mode.value,
            "hosts": hosts,
            "vulns": vulns,
            "notes": list(set(notes)),
        }
        self._tick("scan complete", 100)
        return report

    # ---- steps -------------------------------------------------------------

    def _db_nmap(self, target: str, args: List[str]):
        raw = target
        try:
            raw = str(ipaddress.ip_address(target))
        except ValueError:
            pass
        # db_nmap writes host/service/vuln rows straight into the Metasploit DB
        # (reuses the framework's nmap + import path rather than reimplementing).
        cmd = ["db_nmap"] + args + [raw]
        self._msfconsole_run(cmd)

    def _msfconsole_run(self, argv: List[str]) -> str:
        # The DB is already connected by msfrpcd, so just run db_nmap.
        cmd_str = " ".join(argv)
        cli = f"msfconsole -q -x '{cmd_str};' </dev/null"
        proc = subprocess.run(["bash", "-lc", cli], capture_output=True,
                              text=True, timeout=3600)
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
                hosts.append({
                    "address": addr,
                    "hostname": rec.get("name") or None,
                    "os": rec.get("os_name") or rec.get("os_flavor") or None,
                    "state": rec.get("state"),
                    "services": [],
                })
        except Exception as exc:
            logger.warning("hosts() failed: %s", exc)

        try:
            for rec in self.msf.services(ws):
                addr = rec.get("host") or rec.get("host_id")
                if not _target_matches(str(addr), target):
                    continue
                for host in hosts:
                    if host["address"] == str(addr):
                        host["services"].append({
                            "port": rec.get("port"),
                            "proto": rec.get("proto"),
                            "service": rec.get("name"),
                            "state": rec.get("state"),
                            "info": rec.get("info"),
                        })
        except Exception as exc:
            logger.warning("services() failed: %s", exc)
        return hosts

    def _run_aux_scanners(self, hosts: list, mode, timeout: float = 200.0):
        import time
        launched: list[tuple[int, str, int]] = []  # job_id, module, deadline
        for host in hosts:
            addr = host["address"]
            for svc in host["services"]:
                for module in scanners_for_service(svc.get("service") or ""):
                    opts = {"RHOSTS": addr}
                    if svc.get("port"):
                        opts["RPORT"] = svc["port"]
                    if mode.proxies:
                        opts["Proxies"] = mode.proxies
                    try:
                        res = self.msf.execute("auxiliary", module, opts)
                        if isinstance(res, dict) and res.get("job_id") is not None:
                            launched.append((res["job_id"], module, res.get("uuid", "")))
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
                vulns.append({
                    "name": rec.get("name") or rec.get("info") or "unknown",
                    "refs": rec.get("refs") or [],
                    "port": rec.get("port"),
                    "info": rec.get("info"),
                })
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

    # ---- DNS recon via Greg's bash tools -----------------------------------

    def _dns_recon(self, domain: str) -> list:
        notes = []
        tool_map = {
            "dns_dumpster.sh": ["dns_dumpster.sh", domain],
            "sub_domain_lookup.sh": ["sub_domain_lookup.sh", domain],
        }
        for name, argv in tool_map.items():
            try:
                proc = subprocess.run(argv, capture_output=True, text=True,
                                       timeout=300, cwd="/opt/h4k/scripts")
                if proc.stdout.strip():
                    notes.append(f"[{name}] {proc.stdout.strip()[:300]}")
            except Exception as exc:
                logger.warning("dns tool %s failed: %s", name, exc)
        return notes


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
