# Offline lookup over the curated local CVE database bundled in the image.
# Matches found services (and vuln names/refs) against known CVEs to enrich
# vulnerability findings and recommendations. Optionally refreshable online.
import json
import logging
import urllib.request
from pathlib import Path
from typing import Any, List, Optional

from schemas import Host, Service, Vuln

logger = logging.getLogger("h4k.cve")

DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "cves.json"

# Remote source for optional online refresh (fallback if unreachable -> offline).
REFRESH_URL = (
    "https://raw.githubusercontent.com/Greg-2600/h4k/main/data/cves.json"
)


class CveDb:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path or DATA_FILE)
        self.cves: List[dict] = []
        self.reload()

    def reload(self):
        if not self.path.exists():
            logger.warning("CVE data not found at %s", self.path)
            self.cves = []
            return
        try:
            with open(self.path, encoding="utf-8") as fh:
                data = json.load(fh)
            self.cves = data.get("cves", [])
            logger.info("loaded %d CVEs from %s", len(self.cves), self.path)
        except Exception as exc:
            logger.exception("failed to load CVE data: %s", exc)
            self.cves = []

    # ---- matching ----------------------------------------------------------

    def match_service(self, svc: Service) -> List[dict]:
        """Return CVEs relevant to a discovered service, sorted by CVSS desc."""
        if not self.cves:
            return []
        banner = f"{svc.service or ''} {svc.info or ''}".lower()
        banner_words = set(banner.replace("(", " ").replace(")", " ").split())
        hits = []
        for cve in self.cves:
            product = str(cve.get("product", "")).lower()
            # Strong match: the CVE's specific product token appears in banner
            # (e.g. "openssl", "postgresql", "ssh" in OpenSSH banner).
            if product and product in banner_words:
                hits.append(cve)
                continue
            # Otherwise, only fall back for a known-broad product if the
            # product word is somewhere in the banner text.
            if product and product in banner:
                hits.append(cve)
        return sorted(hits, key=lambda c: -float(c.get("cvss", 0.0)))

    def match_refs(self, refs: List[str]) -> List[dict]:
        """Return CVEs whose ID/alias appears in the refs of a finding."""
        if not refs:
            return []
        text = " ".join(refs).lower()
        out = []
        for cve in self.cves:
            ids = [cve.get("id", "").lower()] + [
                a.lower() for a in cve.get("aliases", [])
            ]
            if any(i and i in text for i in ids):
                out.append(cve)
        return out

    # ---- refresh ----------------------------------------------------------

    def refresh(self, url: str | None = None, timeout: float = 10.0) -> bool:
        """Best-effort online refresh. Returns True if updated.

        Pulls a remote copy of the curated dataset (defaults to the project's
        GitHub copy). On any failure, the bundled snapshot is kept and the
        tool remains fully offline-functional.
        """
        url = url or REFRESH_URL
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            if not isinstance(payload, dict) or "cves" not in payload:
                logger.warning("remote CVE payload missing 'cves'; keeping local")
                return False
            self.path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            self.cves = payload["cves"]
            logger.info("refreshed CVE db from %s (%d CVEs)", url, len(self.cves))
            return True
        except Exception as exc:
            logger.info("CVE refresh offline or failed (%s); using bundled db", exc)
            return False

    def enrich(self, hosts: List[Host], vulns: List[Vuln]) -> dict:
        """Map host/services and vulns -> matched CVEs.

        Returns {"services": {host_addr: {service_key: [cve,...]}},
                 "vulns":    {vuln_index: [cve,...]}}
        """
        result = {
            "services": {},
            "vulns": {},
        }
        if not self.cves:
            return result

        for host in hosts:
            for svc in host.services:
                matched = self.match_service(svc)
                if not matched:
                    continue
                key = f"{host.address}:{svc.port}"
                result["services"].setdefault(host.address, {})[key] = matched

        for idx, vuln in enumerate(vulns):
            matched = self.match_refs(vuln.refs)
            if matched:
                result["vulns"][idx] = matched
        return result
