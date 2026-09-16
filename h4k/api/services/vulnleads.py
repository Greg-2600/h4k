# Flags 'likely-unpatched' / end-of-life / beta / unusual service versions from
# banners as research leads. A lead is a hint to investigate a specific build
# for NEW vulnerabilities — combined with lab fuzzing, this is how fresh bug
# candidates are surfaced. Best-effort heuristic; not a substitute for reading
# vendor advisories.
import logging
import re
from typing import Any

logger = logging.getLogger("h4k.vulnleads")

# product (as shown in banner) -> (regex to pull version, eol_version_marker, note)
# We keep a small, high-value table. Full EOL lists live out of scope on purpose.
PRODUCT_RULES: dict[str, dict[str, Any]] = {
    "openssh": {
        "patterns": [r"[Oo]penSSH[ _]([\d.]+p?\d?)"],
        "eol_below": (7, 0),  # below 7.0 is very old
        "note": "OpenSSH < 7.0 is far out of support; likely unpatched.",
        "cve": "https://nvd.nist.gov/vuln/detail/CVE-2018-15473",
    },
    "apache": {
        "patterns": [r"Apache/([\d.]+)"],
        "eol_below": (2, 4, 0),
        "note": "Apache < 2.4 likely missing a decade of patches.",
        "cve": "https://httpd.apache.org/security/vulnerabilities.html",
    },
    "nginx": {
        "patterns": [r"nginx/([\d.]+)"],
        "eol_below": (1, 18, 0),
        "note": "nginx mainline 1.18 and older are stale.",
        "cve": "https://nginx.org/en/security_advisories.html",
    },
    "php": {
        "patterns": [r"PHP/([\d.]+)"],
        "eol_below": (8, 1, 0),
        "note": "PHP 8.0 and older are end-of-life; unpatched vulns abound.",
        "cve": "https://www.php.net/supported-versions.php",
    },
    "iis": {
        "patterns": [r"Microsoft-IIS/([\d.]+)"],
        "eol_below": (8, 5),
        "note": "IIS 7.5/8.0 are EOL.",
        "cve": "https://learn.microsoft.com/en-us/windows/win32/win7appqual/"
        "applications-and-the-internet-information-services-iis",
    },
    "tomcat": {
        "patterns": [r"Apache Tomcat[/ ]([\d.]+)"],
        "eol_below": (9, 0, 0),
        "note": "Tomcat 8 and older are EOL.",
        "cve": "https://tomcat.apache.org/whichversion.html",
    },
    "vsftpd": {
        "patterns": [r"vsftpd ([\d.]+)"],
        "eol_below": (3, 0, 3),
        "note": "vsftpd below 3.0.3 (and the 2.3.4 backdoor) are notable.",
        "cve": "https://nvd.nist.gov/vuln/detail/CVE-2011-2523",
    },
}

BETA_MARKERS = ("beta", "rc", "pre", "dev", "alpha", "snapshot", "nightly", "unstable")


def _parse_version(s: str) -> tuple[int, ...]:
    m = re.search(r"(\d+(?:\.\d+)+)", s)
    if not m:
        return ()
    return tuple(int(x) for x in m.group(1).split(".")[:4])


def _lt(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    av = a + (0,) * (len(b) - len(a))
    bv = b + (0,) * (len(a) - len(b))
    return av < bv


def analyze_service(host: str, name: str, info: str) -> list[dict]:
    """Return version leads for a single service banner."""
    if not info:
        return []
    product = _match_product(name, info)
    if not product:
        return []
    rule = PRODUCT_RULES[product]
    ver = _extract_version(info, rule["patterns"])
    if not ver:
        # no version parsed; maybe flag beta/unusual
        if any(b in info.lower() for b in BETA_MARKERS):
            return _lead(host, name, info, product, ver, "beta")
        return []

    level = "old" if _lt(ver, rule["eol_below"]) else "unknown"
    if any(b in info.lower() for b in BETA_MARKERS):
        level = "beta"
    if level in ("old", "beta"):
        return _lead(host, name, info, product, ver, level, rule)
    return []


def _lead(
    host: str,
    name: str | None,
    info: str,
    product: str,
    ver: tuple[int, ...],
    level: str,
    rule: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    reason = rule["note"] if rule else f"{product} is a beta/unusual build."
    vstr = ".".join(str(x) for x in ver) if ver else ""
    return [
        {
            "host": host,
            "service": name or "",
            "version": vstr or info[:40],
            "product": product,
            "level": level,
            "reason": reason,
            "cve_link": rule["cve"] if rule else None,
        }
    ]


def _match_product(name: str, info: str) -> str | None:
    blob = f"{name or ''} {info}".lower()
    for product in PRODUCT_RULES:
        if product in blob:
            return product
    return None


def _extract_version(info: str, patterns: list[str]) -> tuple[int, ...]:
    for pat in patterns:
        m = re.search(pat, info)
        if m:
            return _parse_version(m.group(1))
    return _parse_version(info)
