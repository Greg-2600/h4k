# CVE Intelligence Service - Queries multiple CVE databases and vulnerability sources.
# Supports NVD, OSV, GitHub Security Advisories, OSV.dev, and custom databases.
import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger("h4k.cve_intel")

# CVE data sources
CVE_SOURCES = {
    "nvd": {
        "base_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "rate_limit": 0.6,  # seconds between requests (no API key)
        "api_key_env": "NVD_API_KEY",
        "enabled": True,
    },
    "osv": {
        "base_url": "https://api.osv.dev/v1/vulns",
        "rate_limit": 1.0,
        "enabled": True,
    },
    "github": {
        "base_url": "https://api.github.com/advisories",
        "rate_limit": 1.0,
        "api_key_env": "GITHUB_TOKEN",
        "enabled": True,
    },
    "cve_org": {
        "base_url": "https://cveawg.mitre.org/api/cve",
        "rate_limit": 1.0,
        "enabled": True,
    },
}

# Local CVE database path
CVE_DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "cves.json"


class CVESource:
    """Base class for CVE data sources."""

    def __init__(self, name: str, config: dict):
        self.name = name
        self.config = config
        self.last_request: float = 0.0
        self.session = requests.Session()
        self._setup_session()

    def _setup_session(self) -> None:
        headers = {"User-Agent": "h4k-cve-intel/1.0"}
        api_key = self.config.get("api_key_env")
        if api_key and api_key in os.environ:
            if self.name == "nvd":
                self.session.headers["apiKey"] = os.environ[api_key]
            elif self.name == "github":
                self.session.headers["Authorization"] = f"token {os.environ[api_key]}"
        self.session.headers.update(headers)

    def _rate_limit(self) -> None:
        elapsed = time.time() - self.last_request
        if elapsed < self.config.get("rate_limit", 1.0):
            time.sleep(self.config["rate_limit"] - elapsed)
        self.last_request = time.time()

    def search(self, query: str, **kwargs: Any) -> list[dict]:
        """Search for CVEs. Override in subclass."""
        raise NotImplementedError

    def get_cve(self, cve_id: str) -> dict | None:
        """Get detailed CVE information."""
        raise NotImplementedError


class NVDSource(CVESource):
    """National Vulnerability Database source."""

    def search(self, query: str, **kwargs: Any) -> list[dict]:
        self._rate_limit()
        params = {
            "keywordSearch": query,
            "resultsPerPage": kwargs.get("limit", 20),
        }
        if "pubStartDate" in kwargs:
            params["pubStartDate"] = kwargs["pubStartDate"]
        if "pubEndDate" in kwargs:
            params["pubEndDate"] = kwargs["pubEndDate"]
        if "cvssV3Severity" in kwargs:
            params["cvssV3Severity"] = kwargs["cvssV3Severity"]

        url = self.config["base_url"]
        try:
            self._rate_limit()
            resp = self.session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return self._parse_nvd_response(data)
        except Exception as e:
            logger.error(f"NVD search failed: {e}")
            return []

    def get_cve(self, cve_id: str) -> dict | None:
        self._rate_limit()
        url = f"{self.config['base_url']}?cveId={cve_id}"
        try:
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return self._parse_nvd_vuln(vulns[0])
        except Exception as e:
            logger.error(f"NVD get CVE failed: {e}")
        return None

    def _parse_nvd_response(self, data: dict) -> list[dict]:
        vulns = data.get("vulnerabilities", [])
        return [self._parse_nvd_vuln(v) for v in vulns]

    def _parse_nvd_vuln(self, vuln: dict) -> dict:
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})

        return {
            "id": cve.get("id"),
            "description": next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "",
            ),
            "published": cve.get("published"),
            "modified": cve.get("lastModified"),
            "cvss_v3_score": cvss_v3.get("baseScore"),
            "cvss_v3_severity": cvss_v3.get("baseSeverity"),
            "cvss_v2_score": cvss_v2.get("baseScore"),
            "cvss_v2_severity": cvss_v2.get("baseSeverity"),
            "vector_v3": cvss_v3.get("vectorString"),
            "vector_v2": cvss_v2.get("vectorString"),
            "references": [r["url"] for r in cve.get("references", [])],
            "weaknesses": [
                w["description"][0]["value"]
                for w in cve.get("weaknesses", [])
                if w.get("description")
            ],
            "configurations": cve.get("configurations", []),
            "source": "nvd",
        }


class OSVSource(CVESource):
    """Open Source Vulnerabilities database (osv.dev)."""

    def search(self, query: str, **kwargs: Any) -> list[dict]:
        self._rate_limit()
        url = self.config["base_url"]
        params = {"q": query}
        if "limit" in kwargs:
            params["limit"] = kwargs["limit"]
        try:
            resp = self.session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return [self._parse_osv_vuln(v) for v in data.get("vulns", [])]
        except Exception as e:
            logger.error(f"OSV search failed: {e}")
            return []

    def get_cve(self, cve_id: str) -> dict | None:
        self._rate_limit()
        url = f"{self.config['base_url']}/{cve_id}"
        try:
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            return self._parse_osv_vuln(resp.json())
        except Exception as e:
            logger.error(f"OSV get CVE failed: {e}")
            return None

    def _parse_osv_vuln(self, vuln: dict) -> dict:
        severity = "UNKNOWN"
        cvss_score = None
        for sev in vuln.get("severity", []):
            if sev.get("type") == "CVSS_V3":
                severity = sev.get("score", "UNKNOWN")
                cvss_score = sev.get("score")

        return {
            "id": vuln.get("id"),
            "summary": vuln.get("summary", ""),
            "details": vuln.get("details", ""),
            "aliases": vuln.get("aliases", []),
            "modified": vuln.get("modified"),
            "published": vuln.get("published"),
            "severity": severity,
            "cvss_score": cvss_score,
            "references": [r.get("url") for r in vuln.get("references", [])],
            "affected": vuln.get("affected", []),
            "source": "osv",
        }


class GitHubSource(CVESource):
    """GitHub Security Advisories."""

    def search(self, query: str, **kwargs: Any) -> list[dict]:
        self._rate_limit()
        url = self.config["base_url"]
        params = {"q": query, "per_page": kwargs.get("limit", 20)}
        try:
            resp = self.session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return [self._parse_gh_advisory(a) for a in data]
        except Exception as e:
            logger.error(f"GitHub search failed: {e}")
            return []

    def get_cve(self, cve_id: str) -> dict | None:
        self._rate_limit()
        url = f"{self.config['base_url']}/{cve_id}"
        try:
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            return self._parse_gh_advisory(resp.json())
        except Exception as e:
            logger.error(f"GitHub get advisory failed: {e}")
            return None

    def _parse_gh_advisory(self, advisory: dict) -> dict:
        return {
            "id": advisory.get("ghsa_id"),
            "cve_id": advisory.get("cve_id"),
            "summary": advisory.get("summary"),
            "description": advisory.get("description"),
            "severity": advisory.get("severity"),
            "cvss_score": advisory.get("cvss", {}).get("score"),
            "vector": advisory.get("cvss", {}).get("vector_string"),
            "published": advisory.get("published_at"),
            "updated": advisory.get("updated_at"),
            "references": [r["url"] for r in advisory.get("references", [])],
            "vulnerabilities": advisory.get("vulnerabilities", []),
            "source": "github",
        }


class LocalCVESource(CVESource):
    """Local curated CVE database."""

    def __init__(self, path: Path | str = CVE_DB_PATH):
        super().__init__("local", {})
        self.path = Path(path)
        self.cves: list[dict] = []
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                with open(self.path, encoding="utf-8") as f:
                    data = json.load(f)
                    self.cves = data.get("cves", [])
                logger.info(f"Loaded {len(self.cves)} CVEs from local database")
            except Exception as e:
                logger.error(f"Failed to load local CVE db: {e}")
                self.cves = []

    def search(self, query: str, **kwargs: Any) -> list[dict]:
        query_lower = query.lower()
        results = []
        for cve in self.cves:
            if (
                query_lower in cve.get("id", "").lower()
                or query_lower in cve.get("title", "").lower()
                or query_lower in cve.get("description", "").lower()
                or query_lower in cve.get("product", "").lower()
            ):
                results.append(cve)
                if len(results) >= kwargs.get("limit", 20):
                    break
        return results

    def get_cve(self, cve_id: str) -> dict | None:
        for cve in self.cves:
            if cve.get("id") == cve_id:
                return cve
        return None

    def get_all(self) -> list[dict]:
        return self.cves


class CVEIntelligence:
    """Main CVE intelligence orchestrator."""

    def __init__(self) -> None:
        self.sources: list[CVESource] = []
        self.local = LocalCVESource()
        self._init_sources()
        self.cache: dict[str, tuple[datetime, list[dict]]] = {}
        self.cache_ttl = timedelta(hours=24)

    def _init_sources(self) -> None:
        # Initialize enabled sources
        if CVE_SOURCES["nvd"]["enabled"]:
            self.sources.append(NVDSource("nvd", CVE_SOURCES["nvd"]))
        if CVE_SOURCES["osv"]["enabled"]:
            self.sources.append(OSVSource("osv", CVE_SOURCES["osv"]))
        if CVE_SOURCES["github"]["enabled"]:
            self.sources.append(GitHubSource("github", CVE_SOURCES["github"]))
        # Always include local
        self.sources.append(self.local)

    def search_all(self, query: str, **kwargs: Any) -> dict[str, list[dict]]:
        """Search all enabled sources."""
        results = {}
        for source in self.sources:
            try:
                results[source.name] = source.search(query, **kwargs)
            except Exception as e:
                logger.error(f"Search failed for {source.name}: {e}")
                results[source.name] = []
        return results

    def get_cve_details(self, cve_id: str) -> dict | None:
        """Get detailed CVE info from all sources."""
        merged: dict[str, Any] = {"id": cve_id, "sources": {}}
        for source in self.sources:
            try:
                detail = source.get_cve(cve_id)
                if detail:
                    merged["sources"][source.name] = detail
                    # Merge key fields
                    for key in [
                        "description",
                        "cvss_v3_score",
                        "cvss_v3_severity",
                        "cvss_v2_score",
                        "references",
                        "weaknesses",
                        "published",
                        "modified",
                    ]:
                        if key in detail and key not in merged:
                            merged[key] = detail[key]
            except Exception as e:
                logger.error(f"Error getting CVE from {source.name}: {e}")
        return merged if merged["sources"] else None

    def search_by_product(
        self, product: str, version: str | None = None, **kwargs: Any
    ) -> list[dict]:
        """Search for CVEs affecting a specific product/version."""
        query = f"{product} {version}" if version else product
        results = self.search_all(query)
        merged = []
        for source_name, results_list in results.items():
            for cve in results_list:
                cve["source"] = source_name
                merged.append(cve)

        # Deduplicate by CVE ID
        seen = set()
        deduped = []
        for cve in merged:
            cid = cve.get("id") or cve.get("id")
            if cid and cid not in seen:
                seen.add(cid)
                deduped.append(cve)
        return deduped

    def get_affected_versions(self, cve_id: str) -> list[str]:
        """Get affected version ranges for a CVE."""
        detail = self.get_cve_details(cve_id)
        if not detail:
            return []

        affected = []
        for _source_name, source_data in detail.get("sources", {}).items():
            # Parse affected versions from configurations
            configs = source_data.get("configurations", [])
            for config in configs:
                for node in config.get("nodes", []):
                    for cpe in node.get("cpeMatch", []):
                        if cpe.get("vulnerable"):
                            criteria = cpe.get("criteria", "")
                            if "cpe:2.3:" in criteria:
                                parts = criteria.split(":")
                                if len(parts) >= 6:
                                    version = parts[5]
                                    if version != "*":
                                        affected.append(version)
        return list(set(affected))


# Convenience functions
def search_cves(query: str, **kwargs: Any) -> dict[str, list[dict]]:
    """Quick search across all sources."""
    intel = CVEIntelligence()
    return intel.search_all(query, **kwargs)


def get_cve_details(cve_id: str) -> dict | None:
    """Get detailed CVE information from all sources."""
    intel = CVEIntelligence()
    return intel.get_cve_details(cve_id)


def search_by_product(product: str, version: str | None = None) -> list[dict]:
    """Search for CVEs affecting a specific product/version."""
    intel = CVEIntelligence()
    return intel.search_by_product(product, version)


def get_affected_versions(cve_id: str) -> list[str]:
    """Get affected version ranges for a CVE."""
    intel = CVEIntelligence()
    return intel.get_affected_versions(cve_id)


# Export main classes
__all__ = [
    "CVEIntelligence",
    "CVESource",
    "GitHubSource",
    "LocalCVESource",
    "NVDSource",
    "OSVSource",
    "get_affected_versions",
    "get_cve_details",
    "search_by_product",
    "search_cves",
]
