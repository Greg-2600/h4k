# Advanced version detection from service banners and protocol interactions.
# Extracts detailed version information from various protocols and services.
import logging
import re
from typing import Any

logger = logging.getLogger("h4k.version_detector")

# Version extraction patterns for common services
VERSION_PATTERNS: dict[str, list[dict[str, Any]]] = {
    "ssh": [
        {"pattern": r"SSH-([\d.]+)", "group": 1, "type": "version"},
        {"pattern": r"OpenSSH[ _]([\d.]+p?\d*)", "group": 1, "type": "version"},
        {"pattern": r"SSH-2\.0-([\w\-.]+)", "group": 1, "type": "software"},
    ],
    "http": [
        {"pattern": r"Server:\s*([^\r\n]+)", "group": 1, "type": "server"},
        {"pattern": r"X-Powered-By:\s*([^\r\n]+)", "group": 1, "type": "powered_by"},
        {"pattern": r"X-AspNet-Version:\s*([\d.]+)", "group": 1, "type": "version"},
    ],
    "ftp": [
        {"pattern": r"220\s+([^\r\n]+)", "group": 1, "type": "banner"},
        {"pattern": r"vsftpd\s+([\d.]+)", "group": 1, "type": "version"},
        {"pattern": r"ProFTPD\s+([\d.]+)", "group": 1, "type": "version"},
    ],
    "smtp": [
        {"pattern": r"220\s+([^\r\n]+)", "group": 1, "type": "banner"},
        {"pattern": r"ESMTP\s+([\w\-.]+)", "group": 1, "type": "software"},
    ],
    "imap": [
        {"pattern": r"\* OK\s+([^\r\n]+)", "group": 1, "type": "banner"},
    ],
    "pop3": [
        {"pattern": r"\+OK\s+([^\r\n]+)", "group": 1, "type": "banner"},
    ],
    "dns": [
        {"pattern": r"BIND\s+([\d.]+)", "group": 1, "type": "version"},
        {"pattern": r"PowerDNS\s+([\d.]+)", "group": 1, "type": "version"},
    ],
    "mysql": [
        {"pattern": r"(\d+\.\d+\.\d+)", "group": 1, "type": "version"},
        {"pattern": r"MariaDB\s+([\d.]+)", "group": 1, "type": "version"},
    ],
    "postgresql": [
        {"pattern": r"PostgreSQL\s+([\d.]+)", "group": 1, "type": "version"},
    ],
    "redis": [
        {"pattern": r"redis_version:([\d.]+)", "group": 1, "type": "version"},
        {"pattern": r"Redis\s+([\d.]+)", "group": 1, "type": "version"},
    ],
    "mongodb": [
        {"pattern": r"MongoDB\s+([\d.]+)", "group": 1, "type": "version"},
    ],
    "kafka": [
        {"pattern": r"kafka_([\d.]+)", "group": 1, "type": "version"},
    ],
    "elasticsearch": [
        {"pattern": r"elasticsearch[/ ]([\d.]+)", "group": 1, "type": "version"},
    ],
    "jenkins": [
        {"pattern": r"Jenkins\s+([\d.]+)", "group": 1, "type": "version"},
    ],
    "gitlab": [
        {"pattern": r"GitLab/([\d.]+)", "group": 1, "type": "version"},
    ],
    "github": [
        {"pattern": r"GitHub[^/]*/([\d.]+)", "group": 1, "type": "version"},
    ],
    "nginx": [
        {"pattern": r"nginx/([\d.]+)", "group": 1, "type": "version"},
    ],
    "apache": [
        {"pattern": r"Apache/([\d.]+)", "group": 1, "type": "version"},
    ],
    "iis": [
        {"pattern": r"Microsoft-IIS/([\d.]+)", "group": 1, "type": "version"},
    ],
    "tomcat": [
        {"pattern": r"Apache Tomcat/([\d.]+)", "group": 1, "type": "version"},
    ],
    "jetty": [
        {"pattern": r"Jetty/([\d.]+)", "group": 1, "type": "version"},
    ],
    "php": [
        {"pattern": r"PHP/([\d.]+)", "group": 1, "type": "version"},
    ],
    "node": [
        {"pattern": r"node/([\d.]+)", "group": 1, "type": "version"},
        {"pattern": r"Express/([\d.]+)", "group": 1, "type": "version"},
    ],
    "python": [
        {"pattern": r"Python/([\d.]+)", "group": 1, "type": "version"},
    ],
    "perl": [
        {"pattern": r"mod_perl/([\d.]+)", "group": 1, "type": "version"},
    ],
    "ruby": [
        {"pattern": r"Ruby/([\d.]+)", "group": 1, "type": "version"},
    ],
    "java": [
        {"pattern": r"Java/([\d.]+)", "group": 1, "type": "version"},
        {"pattern": r"Apache Tomcat/([\d.]+)", "group": 1, "type": "version"},
    ],
    "dotnet": [
        {"pattern": r"ASP\.NET/([\d.]+)", "group": 1, "type": "version"},
        {"pattern": r"Microsoft-HTTPAPI/([\d.]+)", "group": 1, "type": "version"},
    ],
}


# Version normalization for comparison
def normalize_version(version: str) -> tuple[int, ...]:
    """Normalize version string to tuple of integers for comparison."""
    # Remove common suffixes
    version = re.sub(r"[^\d\.]+", "", version)
    # Split by dots and convert to integers
    parts = []
    for part in version.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            # Handle non-numeric parts (alpha, beta, rc, etc.)
            match = re.match(r"(\d+)([a-zA-Z]*)", part)
            if match:
                parts.append(int(match.group(1)))
    return tuple(parts)


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings. Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2."""
    n1 = normalize_version(v1)
    n2 = normalize_version(v2)
    if n1 < n2:
        return -1
    elif n1 > n2:
        return 1
    return 0


def extract_versions(banner: str, service: str) -> list[dict[str, str]]:
    """Extract all version information from a banner for a given service."""
    results = []
    banner.lower()

    # Get patterns for this service
    patterns = VERSION_PATTERNS.get(service.lower(), [])

    # Also try generic patterns
    generic_patterns = [
        {"pattern": r"version\s*[:=]\s*([\d.]+)", "group": 1, "type": "version"},
        {"pattern": r"v([\d.]+)", "group": 1, "type": "version"},
        {"pattern": r"version\s+([\d.]+)", "group": 1, "type": "version"},
    ]

    all_patterns = patterns + generic_patterns

    for pattern_info in all_patterns:
        pattern = pattern_info["pattern"]
        group = pattern_info.get("group", 1)
        vtype = pattern_info.get("type", "version")
        matches = re.finditer(pattern, banner, re.IGNORECASE)
        for match in matches:
            try:
                version = (
                    match.group(group)
                    if group <= len(match.groups())
                    else match.group(0)
                )
                results.append(
                    {
                        "version": version,
                        "type": vtype,
                        "source": "banner",
                        "pattern": pattern,
                    }
                )
            except IndexError:
                continue

    return results


def detect_software(banner: str, port: int, protocol: str) -> dict[str, Any]:
    """Detect software name and version from banner."""
    result: dict[str, Any] = {"product": None, "version": None, "extra": {}}

    banner_lower = banner.lower()

    # Known service fingerprints
    fingerprints = {
        "ssh": {
            "patterns": [r"ssh", r"openssh"],
            "version_patterns": [
                r"OpenSSH[ _]([\d.]+p?\d*)",
                r"SSH-2\.0-OpenSSH_([\d.]+)",
            ],
        },
        "http": {
            "patterns": [r"http", r"apache", r"nginx", r"iis", "lighttpd"],
            "version_patterns": [
                r"Server:\s*([^\r\n]+)",
                r"Apache/([\d.]+)",
                r"nginx/([\d.]+)",
                r"Microsoft-IIS/([\d.]+)",
            ],
        },
        "ftp": {
            "patterns": [r"ftp", "vsftpd", "proftpd", "pure-ftpd"],
            "version_patterns": [
                r"vsftpd\s+([\d.]+)",
                r"ProFTPD\s+([\d.]+)",
                r"Pure-FTPd\s+([\d.]+)",
            ],
        },
        "smtp": {
            "patterns": [r"smtp", "postfix", "exim", "sendmail", "qmail"],
            "version_patterns": [
                r"Postfix\s*\(?\)?\s*([\d.]+)",
                r"Exim\s+([\d.]+)",
            ],
        },
        "redis": {
            "patterns": [r"redis"],
            "version_patterns": [r"redis_version:([\d.]+)", r"Redis\s+([\d.]+)"],
        },
        "mongodb": {
            "patterns": [r"mongodb"],
            "version_patterns": [r"MongoDB\s+([\d.]+)"],
        },
        "postgresql": {
            "patterns": [r"postgresql"],
            "version_patterns": [r"PostgreSQL\s+([\d.]+)"],
        },
        "mysql": {
            "patterns": [r"mysql", "mariadb"],
            "version_patterns": [r"(\d+\.\d+\.\d+)", r"MariaDB\s+([\d.]+)"],
        },
    }

    for service_name, fp in fingerprints.items():
        for pattern in fp["patterns"]:
            if re.search(pattern, banner_lower, re.IGNORECASE):
                result["product"] = service_name
                # Try to extract version
                for vp in fp["version_patterns"]:
                    match = re.search(vp, banner, re.IGNORECASE)
                    if match:
                        result["version"] = match.group(1)
                        break
                return result

    return result


class VersionDetector:
    """Advanced version detection from service banners."""

    def __init__(self) -> None:
        self.logger = logging.getLogger("h4k.version_detector")

    def detect(self, banner: str, port: int, protocol: str = "tcp") -> dict[str, Any]:
        """Detect software and version from banner."""
        if not banner:
            return {"product": None, "version": None, "extra": {}}

        # Try specific service detection
        result = detect_software(banner, 0, "tcp")

        # If no product detected, try generic extraction
        if not result["product"]:
            result["product"] = "unknown"
            # Try generic version extraction
            generic_version = re.search(r"(\d+\.\d+\.\d+)", banner)
            if generic_version:
                result["version"] = generic_version.group(1)

        # Extract all versions found
        versions = extract_versions(banner, "unknown")
        result["extra"]["all_versions"] = versions

        return result

    def detect_from_http_headers(self, headers: dict) -> dict[str, Any]:
        """Extract version info from HTTP headers."""
        result: dict[str, Any] = {"product": None, "version": None, "extra": {}}
        server = headers.get("Server", "")
        if server:
            result["product"] = "http"
            # Try to extract version from server header
            version_match = re.search(r"(\d+\.\d+\.\d+)", server)
            if version_match:
                result["version"] = version_match.group(1)
            else:
                result["version"] = server[:50]

        # Check other headers
        powered_by = headers.get("X-Powered-By", "")
        if powered_by:
            result["extra"]["powered_by"] = powered_by

        return result


def parse_version(version_str: str) -> tuple:
    """Parse version string into tuple for comparison."""
    # Remove non-numeric prefixes/suffixes
    version_str = re.sub(r"^[^\d]+", "", version_str)
    version_str = re.sub(r"[^\d\.]+$", "", version_str)

    parts = []
    for part in version_str.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            # Handle alpha/beta/rc suffixes
            match = re.match(r"(\d+)([a-zA-Z]*)", part)
            if match:
                parts.append(int(match.group(1)))
    return tuple(parts)


def is_version_vulnerable(
    version: str, min_version: str | None = None, max_version: str | None = None
) -> bool:
    """Check if version falls within vulnerable range."""
    version_tuple = parse_version(version)

    if min_version:
        min_tuple = parse_version(min_version)
        if version_tuple < min_tuple:
            return False

    if max_version:
        max_tuple = parse_version(max_version)
        if version_tuple > max_tuple:
            return False

    return True


# Common vulnerable version ranges for quick checks
VULNERABLE_RANGES = {
    "openssh": [
        {"min": "0.0.0", "max": "7.9", "cve": "CVE-2018-15473"},
        {"min": "8.0", "max": "8.2", "cve": "CVE-2020-15778"},
        {"min": "0.0.0", "max": "9.2", "cve": "CVE-2023-38408"},
    ],
    "openssl": [
        {"min": "1.0.0", "max": "1.0.2z", "cve": "CVE-2014-0160"},
        {"min": "3.0.0", "max": "3.0.6", "cve": "CVE-2022-0778"},
    ],
    "apache": [
        {"min": "2.4.0", "max": "2.4.49", "cve": "CVE-2021-41773"},
    ],
    "nginx": [
        {"min": "0.0.0", "max": "1.20.0", "cve": "CVE-2021-23017"},
    ],
    # vsftpd 2.3.4 shipped with a backdoor that opens a root shell on 6200.
    # 3.0.3 (and every later release) is not affected -- matching on the
    # service name alone produced a false positive on a patched host.
    "vsftpd": [
        {"min": "2.3.4", "max": "2.3.4", "cve": "CVE-2011-2523"},
    ],
    "wu-ftpd": [
        {"min": "1.0.0", "max": "1.1.3", "cve": "CVE-1999-0527"},
    ],
    "proftpd": [
        {"min": "1.0.0", "max": "1.3.5", "cve": "CVE-2015-3306"},
    ],
    "samba": [
        {"min": "0.0.0", "max": "4.6.9", "cve": "CVE-2017-0144"},
        {"min": "4.7.0", "max": "4.7.11", "cve": "CVE-2020-27840"},
    ],
    "postgresql": [
        {"min": "9.0.0", "max": "9.6.21", "cve": "CVE-2021-35942"},
        {"min": "10.0.0", "max": "10.4.24", "cve": "CVE-2022-21723"},
    ],
    "docker": [
        {"min": "0.0.0", "max": "18.9.9", "cve": "CVE-2019-16239"},
    ],
    "plex": [
        {"min": "1.0.0", "max": "1.19.5", "cve": "CVE-2020-3896"},
    ],
    "sabnzbd": [
        {"min": "0.0.0", "max": "4.2.1", "cve": "CVE-2024-31827"},
    ],
    # Copy Fail (CVE-2026-31431): kernel algif_aead LPE. Two affected
    # branches; 7.x is past the fix (6.18.22+/6.19.12+/7.0+), so a 7.2 host
    # correctly matches nothing here. Plain X.Y.Z bounds: no p-suffix
    # ambiguity (unlike sudo below, which is why sudo has no ranges yet --
    # tuple comparison cannot tell 1.9.17 base from 1.9.17p2, and a
    # max of "1.9.17" would false-positive patched p1/p2 hosts).
    "linux": [
        {"min": "4.14", "max": "6.18.21", "cve": "CVE-2026-31431"},
        {"min": "6.19", "max": "6.19.11", "cve": "CVE-2026-31431"},
    ],
    # Second-order SQLi in ZoneMinder getNearEvents (CVE-2026-27470):
    # entry via event rename/eventdetail, trigger via nearevents endpoint.
    # Proven live on 1.36.35 (UNION exfiltration of Users table); fixed in
    # 1.36.38 / 1.38.1. No file primitives even when injectable when the
    # DB runs with secure_file_priv=NULL.
    "zoneminder": [
        {"min": "1.36.0", "max": "1.36.37", "cve": "CVE-2026-27470"},
        {"min": "1.38.0", "max": "1.38.0", "cve": "CVE-2026-27470"},
    ],
}


def has_version_data(product: str) -> bool:
    """True when we know the vulnerable version ranges for this product.

    The CVE matcher needs this distinction: if we have version data and the
    detected version is outside every vulnerable range, the CVE genuinely does
    not apply. If we have *no* version data, we cannot rule it out -- the match
    stays, but it is marked as unverified rather than presented as fact.
    """
    return str(product or "").lower() in VULNERABLE_RANGES


def check_vulnerable_version(product: str, version: str) -> list[dict]:
    """Check if a product version is in known vulnerable ranges."""
    product_lower = product.lower()
    if product_lower not in VULNERABLE_RANGES:
        return []

    results = []
    for range_info in VULNERABLE_RANGES[product_lower]:
        if is_version_vulnerable(version, range_info.get("min"), range_info.get("max")):
            results.append(
                {
                    "product": product,
                    "version": version,
                    "cve": range_info.get("cve"),
                    "range": (
                        f"{range_info.get('min', '0.0.0')} - "
                        f"{range_info.get('max', '999.999.999')}"
                    ),
                }
            )
    return results
