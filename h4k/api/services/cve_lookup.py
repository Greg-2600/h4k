# Offline lookup over the curated local CVE database bundled in the image.
# Matches found services (and vuln names/refs) against known CVEs to enrich
# vulnerability findings and recommendations. Optionally refreshable online.
import json
import logging
import urllib.request
from pathlib import Path

from schemas import Host, Service, Vuln

logger = logging.getLogger("h4k.cve")

DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "cves.json"

# Remote source for optional online refresh (fallback if unreachable -> offline).
REFRESH_URL = "https://raw.githubusercontent.com/Greg-2600/h4k/main/h4k/data/cves.json"


class CveDb:
    def __init__(self, path: Path | str | None = None):
        self.path = Path(path or DATA_FILE)
        self.cves: list[dict] = []
        self.reload()

    def reload(self) -> None:
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

    def match_service(
        self, svc: Service, version: str | None = None, product: str | None = None
    ) -> list[dict]:
        """Return CVEs relevant to a discovered service, sorted by CVSS desc.

        When version is provided, performs version-aware matching to avoid
        false positives (e.g., matching Heartbleed on any OpenSSL banner).
        """
        if not self.cves:
            return []
        banner = f"{svc.service or ''} {svc.info or ''}".lower()
        banner_words = set(banner.replace("(", " ").replace(")", " ").split())

        # Import here to avoid circular imports at module level
        from services.version_detector import (
            check_vulnerable_version,
            has_version_data,
        )

        # The product we actually detected on the wire ("vsftpd") is what the
        # version ranges are keyed by -- not the CVE's generic product
        # ("ftp"). Using the wrong one produced false positives like
        # "vsftpd 2.3.4 backdoor" on a vsftpd 3.0.3 host.
        version_product = (product or "").lower()

        hits = []
        for cve in self.cves:
            product_key = str(cve.get("product", "")).lower()
            if not product_key:
                continue

            # Check if product matches banner
            product_match = product_key in banner_words or product_key in banner

            if not product_match:
                continue

            # Version-aware matching: if we know the version AND we know the
            # vulnerable ranges for the detected product, the CVE only applies
            # when the version is inside one of them.
            if version and version_product:
                vulnerable = check_vulnerable_version(version_product, version)
                if vulnerable:
                    # Filter CVEs to only those affecting this version range
                    for vuln in vulnerable:
                        if vuln.get("cve") == cve.get("id"):
                            cve_with_version = dict(cve)
                            cve_with_version["_matched_version"] = version
                            cve_with_version["_vulnerable_range"] = vuln.get("range")
                            cve_with_version["_version_verified"] = True
                            hits.append(cve_with_version)
                            break
                    continue
                if has_version_data(version_product):
                    # We know the ranges and this version is outside all of
                    # them: the CVE does not apply to this host.
                    continue

            cve_with_version = dict(cve)
            if version:
                # No version data for this product: we cannot rule the CVE
                # out, but we must not present it as confirmed either.
                cve_with_version["_matched_version"] = version
                cve_with_version["_version_verified"] = False
            hits.append(cve_with_version)

        return sorted(hits, key=lambda c: -float(c.get("cvss", 0.0)))

    def match_refs(self, refs: list[str]) -> list[dict]:
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
            # URL is a fixed https constant (no user input); allow only http(s).
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # nosec B310
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

    def enrich(
        self,
        hosts: list[Host],
        vulns: list[Vuln],
        fingerprints: list[dict] | None = None,
    ) -> dict:
        """Map host/services and vulns -> matched CVEs.

        When fingerprints with version info are provided, performs
        version-aware CVE matching to reduce false positives.

        Returns {"services": {host_addr: {service_key: [cve,...]}},
                 "vulns":    {vuln_index: [cve,...]}}
        """
        services: dict[str, dict[str, list[dict]]] = {}
        vuln_map: dict[str, list[dict]] = {}
        if not self.cves:
            return {"services": services, "vulns": vuln_map}

        # Build fingerprint lookup by host
        fp_by_host: dict[str, dict] = {}
        if fingerprints:
            for fp in fingerprints:
                fp_by_host[fp.get("host", "")] = fp

        for host in hosts:
            host_fp = fp_by_host.get(host.address, {})
            for svc in host.services:
                matched = self.match_service(
                    svc,
                    version=host_fp.get("version"),
                    product=host_fp.get("product"),
                )
                if not matched:
                    continue
                key = f"{host.address}:{svc.port}"
                services.setdefault(host.address, {})[key] = matched

        for idx, vuln in enumerate(vulns):
            matched = self.match_refs(vuln.refs)
            if matched:
                vuln_map[str(idx)] = matched
        return {"services": services, "vulns": vuln_map}
