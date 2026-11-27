"""OS package audit + base-image freshness (Backlog #70).

Offline analysis for systems you are entitled to assess:

* **OS package audit** parses pasted ``dpkg``/``rpm``/``apk`` inventory output
  and matches package names + versions against a small curated advisory table.
  A package is only marked vulnerable when its parsed version is below the
  curated fixed version; a missing version is reported as unknown, never as a
  hit.
* **Base-image freshness** reads pasted image metadata (``docker inspect`` or
  OCI labels), computes image age, compares the base image family/version
  against a small EOL table, and suggests slimmer, better-pinned alternatives.

Everything is deliberately honest and offline. Nothing talks to a registry,
runs ``docker``/``apt``/``rpm``/``apk``, downloads an advisory, or checks a
signature. The curated tables are tiny by design; absence of a finding is not
proof that a package is patched, and EOL dates are public schedules that can
change. Sandbox mode returns canned data without parsing the request.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from typing import Any

logger = logging.getLogger("h4k.os_package_audit")

LIMITATIONS = (
    "Offline audit only: package inventories are parsed locally and matched "
    "against a small curated advisory table using a simplified version "
    "comparison, and base-image EOL dates come from a small public schedule "
    "snapshot. No registry, package manager, docker daemon or network is "
    "contacted, and signatures are NOT verified. Treat findings as review "
    "leads; absence of a finding is not proof that a package is patched."
)

ALL_ECOSYSTEMS = ("dpkg", "rpm", "apk")

# Curated, stable advisory table. `vulnerable_below` is the first fixed
# upstream version for the named issue. This is intentionally small: it is a
# demonstration corpus, not a replacement for a distro security tracker.
ADVISORIES: tuple[dict[str, Any], ...] = (
    {
        "cve": "CVE-2021-3156",
        "package": "sudo",
        "aliases": ("sudo",),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "1.9.5p2",
        "fixed": "1.9.5p2",
        "severity": "HIGH",
        "cvss": 7.8,
        "summary": "sudo heap buffer overflow (Baron Samedit)",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-3156",
    },
    {
        "cve": "CVE-2014-0160",
        "package": "openssl",
        "aliases": (
            "openssl",
            "openssl-libs",
            "libssl",
            "libssl1.0.0",
            "libssl1.0.2",
            "libssl1.1",
        ),
        "ecosystems": ALL_ECOSYSTEMS,
        "introduced": "1.0.1",
        "vulnerable_below": "1.0.1g",
        "fixed": "1.0.1g",
        "severity": "HIGH",
        "cvss": 7.5,
        "summary": "OpenSSL TLS heartbeat read overrun (Heartbleed)",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
    },
    {
        "cve": "CVE-2022-0778",
        "package": "openssl",
        "aliases": (
            "openssl",
            "openssl-libs",
            "libssl",
            "libssl1.1",
            "libssl3",
        ),
        "ecosystems": ALL_ECOSYSTEMS,
        "introduced": "1.1.1",
        "vulnerable_below": "1.1.1n",
        "fixed": "1.1.1n",
        "severity": "HIGH",
        "cvss": 7.5,
        "summary": "OpenSSL BN_mod_sqrt infinite loop on crafted certificate",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2022-0778",
    },
    {
        "cve": "CVE-2014-6271",
        "package": "bash",
        "aliases": ("bash",),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "4.3.30",
        "fixed": "4.3.30",
        "severity": "HIGH",
        "cvss": 9.8,
        "summary": "GNU Bash environment-function parsing (Shellshock)",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
    },
    {
        "cve": "CVE-2015-0235",
        "package": "glibc",
        "aliases": ("glibc", "libc6", "libc-bin"),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "2.18",
        "fixed": "2.18",
        "severity": "HIGH",
        "cvss": 10.0,
        "summary": "glibc gethostbyname buffer overflow (GHOST)",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2015-0235",
    },
    {
        "cve": "CVE-2018-25032",
        "package": "zlib",
        "aliases": ("zlib", "zlib1g", "zlib-devel", "zlib1"),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "1.2.12",
        "fixed": "1.2.12",
        "severity": "HIGH",
        "cvss": 7.5,
        "summary": "zlib memory corruption while compressing with a big window",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2018-25032",
    },
    {
        "cve": "CVE-2023-38545",
        "package": "curl",
        "aliases": ("curl", "libcurl", "libcurl4", "libcurl-minimal"),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "8.4.0",
        "fixed": "8.4.0",
        "severity": "HIGH",
        "cvss": 8.8,
        "summary": "curl SOCKS5 heap buffer overflow",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2023-38545",
    },
    {
        "cve": "CVE-2023-38408",
        "package": "openssh",
        "aliases": (
            "openssh",
            "openssh-server",
            "openssh-client",
            "openssh-clients",
        ),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "9.3p2",
        "fixed": "9.3p2",
        "severity": "HIGH",
        "cvss": 9.8,
        "summary": "OpenSSH PKCS#11 helper remote code execution",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2023-38408",
    },
    {
        "cve": "CVE-2022-23308",
        "package": "libxml2",
        "aliases": ("libxml2",),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "2.9.13",
        "fixed": "2.9.13",
        "severity": "HIGH",
        "cvss": 7.5,
        "summary": "libxml2 use-after-free in xmlXPtrRangeToFunction",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2022-23308",
    },
    {
        "cve": "CVE-2022-35737",
        "package": "sqlite",
        "aliases": ("sqlite", "sqlite3", "libsqlite3-0", "sqlite-libs"),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "3.39.2",
        "fixed": "3.39.2",
        "severity": "MEDIUM",
        "cvss": 7.5,
        "summary": "SQLite printf integer overflow with large format strings",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2022-35737",
    },
    {
        "cve": "CVE-2022-40674",
        "package": "expat",
        "aliases": ("expat", "libexpat1", "expat-libs"),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "2.4.9",
        "fixed": "2.4.9",
        "severity": "HIGH",
        "cvss": 9.8,
        "summary": "expat use-after-free in doContent",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2022-40674",
    },
    {
        "cve": "CVE-2021-3177",
        "package": "python3",
        "aliases": ("python3", "python3-minimal", "python3-libs", "python"),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "3.9.2",
        "fixed": "3.9.2",
        "severity": "HIGH",
        "cvss": 9.8,
        "summary": "Python PyCArg buffer overflow",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-3177",
    },
    {
        "cve": "CVE-2019-12735",
        "package": "vim",
        "aliases": ("vim", "vim-minimal", "vim-enhanced"),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "8.1.1365",
        "fixed": "8.1.1365",
        "severity": "HIGH",
        "cvss": 9.8,
        "summary": "Vim modeline source command execution",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2019-12735",
    },
    {
        "cve": "CVE-2021-33910",
        "package": "systemd",
        "aliases": ("systemd",),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "248",
        "fixed": "248",
        "severity": "HIGH",
        "cvss": 7.8,
        "summary": "systemd alloca stack exhaustion via crafted unit name",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-33910",
    },
    {
        "cve": "CVE-2021-42386",
        "package": "busybox",
        "aliases": ("busybox",),
        "ecosystems": ALL_ECOSYSTEMS,
        "vulnerable_below": "1.34.0",
        "fixed": "1.34.0",
        "severity": "HIGH",
        "cvss": 9.8,
        "summary": "BusyBox awk use-after-free",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-42386",
    },
    {
        "cve": "CVE-2021-36159",
        "package": "apk-tools",
        "aliases": ("apk-tools",),
        "ecosystems": ("apk",),
        "vulnerable_below": "2.12.6",
        "fixed": "2.12.6",
        "severity": "HIGH",
        "cvss": 9.1,
        "summary": "apk-tools tar extraction out-of-bounds read",
        "advisory": "https://nvd.nist.gov/vuln/detail/CVE-2021-36159",
    },
)

# Small base-image EOL snapshot (public schedules; approximate by design).
BASE_EOL: dict[str, dict[str, str]] = {
    "debian": {
        "9": "2022-06-30",
        "10": "2024-06-30",
        "11": "2026-08-31",
        "12": "2028-06-30",
        "13": "2030-06-30",
    },
    "ubuntu": {
        "16.04": "2021-04-30",
        "18.04": "2023-05-31",
        "20.04": "2025-05-31",
        "22.04": "2027-04-30",
        "24.04": "2029-04-30",
    },
    "alpine": {
        "3.14": "2023-05-01",
        "3.15": "2023-11-01",
        "3.16": "2024-05-23",
        "3.17": "2024-11-22",
        "3.18": "2025-05-09",
        "3.19": "2025-11-01",
        "3.20": "2026-04-01",
        "3.21": "2026-11-01",
        "3.22": "2027-05-01",
    },
    "centos": {"7": "2024-06-30", "8": "2021-12-31"},
    "rhel": {"7": "2024-06-30", "8": "2029-05-31", "9": "2032-05-31"},
    "ubi": {"7": "2024-06-30", "8": "2029-05-31", "9": "2032-05-31"},
    "amazonlinux": {"1": "2023-12-31", "2": "2026-06-30", "2023": "2029-06-30"},
    "fedora": {
        "36": "2023-05-16",
        "37": "2023-12-05",
        "38": "2024-05-21",
        "39": "2024-11-26",
        "40": "2025-05-13",
        "41": "2025-11-30",
    },
}

EOL_APPROACHING_DAYS = 90
VALID_FORMATS = ("auto", "dpkg", "rpm", "apk", "generic")

_DPKG_STATUS = frozenset(
    {
        "ii",
        "rc",
        "hi",
        "un",
        "pn",
        "iU",
        "iF",
        "iH",
        "iW",
        "iT",
        "iR",
        "hU",
        "hF",
        "hW",
        "hT",
        "hR",
        "uU",
        "uF",
        "uW",
        "uT",
        "uR",
        "rU",
        "rF",
        "rW",
        "rT",
        "rR",
        "pU",
        "pF",
        "pW",
        "pT",
        "pR",
    }
)
_HEADER_PREFIXES = (
    "desired=",
    "| status=",
    "||/",
    "+++-",
    "warning:",
    "reading ",
    "listing ",
)
_RPM_ARCH_RE = re.compile(
    r"\.(?:x86_64|aarch64|noarch|i[3-6]86|armv7hl|ppc64le|s390x)$", re.I
)
_RPM_TAG_RE = re.compile(r"\.(?:el|fc)\d+", re.I)
_APK_VERSION_RE = re.compile(r"^(?P<name>.+)-(?P<version>\d[^-]*(?:-r\d+)?)$")
_VERSION_TOKEN_RE = re.compile(r"\d+|[a-z]+")
_ECOSYSTEM_ALIASES = {
    "debian": "dpkg",
    "ubuntu": "dpkg",
    "rpm": "rpm",
    "redhat": "rpm",
    "rhel": "rpm",
    "centos": "rpm",
    "fedora": "rpm",
    "amazon": "rpm",
    "amzn": "rpm",
    "alpine": "apk",
}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _normalize_ecosystem(value: str) -> str:
    lowered = value.strip().lower()
    return _ECOSYSTEM_ALIASES.get(lowered, lowered)


def _clean_name(name: str) -> str:
    cleaned = name.strip().lower()
    if ":" in cleaned:
        cleaned = cleaned.split(":", 1)[0]
    if "/" in cleaned and not cleaned.startswith("@"):
        cleaned = cleaned.rsplit("/", 1)[-1]
    return cleaned


def _version_key(version: str) -> tuple[tuple[int, int, str], ...]:
    """Simplified comparable key: epoch/revision stripped, numeric runs win."""
    core = version.strip().lower()
    if ":" in core:
        core = core.split(":", 1)[1]
    core = core.split("-", 1)[0]
    core = core.split("+", 1)[0]
    tokens: list[tuple[int, int, str]] = []
    for part in _VERSION_TOKEN_RE.findall(core):
        if part.isdigit():
            tokens.append((1, int(part), ""))
        else:
            tokens.append((0, 0, part))
    return tuple(tokens)


def _version_lt(left: str, right: str) -> bool:
    left_key = _version_key(left)
    right_key = _version_key(right)
    if not left_key or not right_key:
        return False
    return left_key < right_key


def _parse_dt(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=UTC)
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _detect_format(line: str) -> str:
    lowered = line.strip().lower()
    tokens = line.split()
    if tokens and tokens[0] in _DPKG_STATUS:
        return "dpkg"
    if _RPM_ARCH_RE.search(line) or _RPM_TAG_RE.search(line):
        return "rpm"
    if re.search(r"-r\d+$", line.strip()):
        return "apk"
    if lowered.startswith(_HEADER_PREFIXES):
        return "header"
    return "generic"


def _parse_rpm_compact(line: str) -> dict[str, str] | None:
    cleaned = _RPM_ARCH_RE.sub("", line.strip())
    parts = cleaned.split("-")
    if len(parts) < 2:
        return None
    if len(parts) >= 3:
        name = "-".join(parts[:-2])
        version = "-".join(parts[-2:])
        if name:
            return {
                "name": _clean_name(name),
                "version": version,
                "ecosystem": "rpm",
            }
    return {"name": _clean_name(parts[0]), "version": parts[1], "ecosystem": "rpm"}


def _parse_apk_compact(line: str) -> dict[str, str] | None:
    match = _APK_VERSION_RE.match(line.strip())
    if not match:
        return None
    return {
        "name": _clean_name(match.group("name")),
        "version": match.group("version"),
        "ecosystem": "apk",
    }


def _parse_line(line: str, fmt: str) -> dict[str, str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    lowered = stripped.lower()
    if lowered.startswith(_HEADER_PREFIXES):
        return None
    if stripped.startswith("Package:") or stripped.startswith("Version:"):
        return None

    tokens = stripped.split()
    if len(tokens) == 1 and "=" in stripped:
        name, _, version = stripped.partition("=")
        if name and version:
            return {
                "name": _clean_name(name),
                "version": version,
                "ecosystem": "",
            }

    detected = _detect_format(stripped)
    if fmt == "auto":
        fmt = detected if detected != "header" else "generic"

    if fmt == "dpkg":
        if len(tokens) >= 3 and tokens[0] in _DPKG_STATUS:
            return {
                "name": _clean_name(tokens[1]),
                "version": tokens[2],
                "ecosystem": "dpkg",
            }
        if len(tokens) >= 2:
            return {
                "name": _clean_name(tokens[0]),
                "version": tokens[1],
                "ecosystem": "dpkg",
            }
        return None

    if fmt == "rpm":
        if len(tokens) >= 2:
            return {
                "name": _clean_name(tokens[0]),
                "version": tokens[1],
                "ecosystem": "rpm",
            }
        return _parse_rpm_compact(stripped)

    if fmt == "apk":
        if len(tokens) >= 2:
            return {
                "name": _clean_name(tokens[0]),
                "version": tokens[1],
                "ecosystem": "apk",
            }
        return _parse_apk_compact(stripped)

    if len(tokens) >= 2:
        return {
            "name": _clean_name(tokens[0]),
            "version": tokens[1],
            "ecosystem": "",
        }
    if "=" in stripped:
        name, _, version = stripped.partition("=")
        if name and version:
            return {
                "name": _clean_name(name),
                "version": version,
                "ecosystem": "",
            }
    return None


def _parse_deb822(text: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            if current.get("name") and current.get("version"):
                packages.append(
                    {
                        "name": current["name"],
                        "version": current["version"],
                        "ecosystem": "dpkg",
                    }
                )
            current = {}
            continue
        if line.startswith("Package:"):
            current["name"] = _clean_name(line.split(":", 1)[1])
        elif line.startswith("Version:"):
            current["version"] = line.split(":", 1)[1].strip()
    if current.get("name") and current.get("version"):
        packages.append(
            {
                "name": current["name"],
                "version": current["version"],
                "ecosystem": "dpkg",
            }
        )
    return packages


def _normalize_entry(entry: Any, fmt: str) -> dict[str, str]:
    if isinstance(entry, str):
        parsed = _parse_line(entry, fmt if fmt != "auto" else "auto")
        if not parsed:
            raise ValueError(f"cannot parse package entry: {entry!r}")
        return parsed
    if isinstance(entry, dict):
        name = str(entry.get("name") or entry.get("package") or "").strip()
        version = str(entry.get("version") or "").strip()
        ecosystem = _normalize_ecosystem(
            str(entry.get("ecosystem") or entry.get("format") or "")
        )
        if not name:
            raise ValueError("package name required")
        return {"name": _clean_name(name), "version": version, "ecosystem": ecosystem}
    raise ValueError("package entries must be strings or objects")


def parse_inventory(text: str, fmt: str = "auto") -> list[dict[str, str]]:
    """Parse pasted dpkg/rpm/apk inventory output into name/version records."""
    if not isinstance(text, str):
        raise ValueError("inventory must be a string")
    if fmt not in VALID_FORMATS:
        raise ValueError("format must be auto, dpkg, rpm, apk or generic")
    if not text.strip():
        return []
    if "Package:" in text and "Version:" in text:
        return _parse_deb822(text)

    packages: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for line in text.splitlines():
        parsed = _parse_line(line, fmt)
        if not parsed:
            continue
        key = (parsed["name"], parsed["version"], parsed["ecosystem"])
        if key in seen:
            continue
        seen.add(key)
        packages.append(parsed)
    return packages


def _package_entry(entry: dict[str, str], fmt: str) -> dict[str, str]:
    ecosystem = entry.get("ecosystem") or (fmt if fmt != "auto" else "generic")
    return {
        "name": entry["name"],
        "version": entry.get("version", ""),
        "ecosystem": ecosystem,
    }


def _matching_advisories(package: dict[str, str]) -> list[dict[str, Any]]:
    name = package["name"]
    ecosystem = package["ecosystem"]
    matches: list[dict[str, Any]] = []
    for advisory in ADVISORIES:
        aliases = advisory.get("aliases") or (advisory.get("package"),)
        if name not in aliases:
            continue
        ecosystems = advisory.get("ecosystems") or ALL_ECOSYSTEMS
        if (
            ecosystem
            and ecosystem not in ("generic", "mixed")
            and ecosystem not in ecosystems
        ):
            continue
        matches.append(advisory)
    return matches


def _advisory_status(package: dict[str, str], advisory: dict[str, Any]) -> str:
    if not package["version"]:
        return "unknown"
    introduced = str(advisory.get("introduced") or "")
    if introduced and _version_lt(package["version"], introduced):
        return "not_affected"
    if _version_lt(package["version"], str(advisory["vulnerable_below"])):
        return "vulnerable"
    return "fixed"


def _package_verdict(package: dict[str, str]) -> dict[str, Any]:
    advisories = _matching_advisories(package)
    statuses = [_advisory_status(package, advisory) for advisory in advisories]
    if "vulnerable" in statuses:
        status = "vulnerable"
    elif "unknown" in statuses:
        status = "unknown"
    elif "fixed" in statuses:
        status = "fixed"
    elif "not_affected" in statuses:
        status = "not_affected"
    else:
        status = "no_advisory"
    hits = [
        str(advisory["cve"])
        for advisory, advisory_status in zip(advisories, statuses, strict=False)
        if advisory_status == "vulnerable"
    ]
    return {
        "name": package["name"],
        "version": package["version"],
        "ecosystem": package["ecosystem"],
        "status": status,
        "advisories": [str(a["cve"]) for a in advisories],
        "vulnerable": hits,
    }


def _finding(package: dict[str, str], advisory: dict[str, Any]) -> dict[str, Any]:
    return {
        "package": package["name"],
        "version": package["version"],
        "ecosystem": package["ecosystem"],
        "cve": advisory["cve"],
        "severity": advisory["severity"],
        "cvss": advisory["cvss"],
        "summary": advisory["summary"],
        "fixed": advisory["fixed"],
        "advisory": advisory["advisory"],
    }


def _image_base(meta: dict[str, Any]) -> str:
    for key in ("base_image", "baseImage", "base", "parent"):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    labels = _as_dict(meta.get("Config", {}).get("Labels")) or _as_dict(
        meta.get("labels") or meta.get("Labels")
    )
    for key in (
        "org.opencontainers.image.base.name",
        "org.opencontainers.image.ref.name",
    ):
        value = labels.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    tags = _as_list(meta.get("RepoTags"))
    if tags and isinstance(tags[0], str):
        return tags[0].strip()
    return ""


def _image_created(meta: dict[str, Any]) -> Any:
    for key in ("Created", "created", "created_at", "createdAt"):
        value = meta.get(key)
        if value:
            return value
    labels = _as_dict(meta.get("Config", {}).get("Labels")) or _as_dict(
        meta.get("labels") or meta.get("Labels")
    )
    return labels.get("org.opencontainers.image.created")


def _image_family_version(base: str) -> tuple[str, str]:
    lowered = base.lower()
    match = re.search(r"(?:^|/)(debian)[:@]?(\d+(?:\.\d+)?)", lowered)
    if match:
        return "debian", match.group(2)
    match = re.search(r"(?:^|/)(ubuntu)[:@]?(\d{2}\.\d{2})", lowered)
    if match:
        return "ubuntu", match.group(2)
    match = re.search(r"(?:^|/)(alpine)[:@]?(\d+\.\d+)", lowered)
    if match:
        return "alpine", match.group(2)
    match = re.search(r"(?:^|/)(centos)[:@]?(\d+)", lowered)
    if match:
        return "centos", match.group(2)
    match = re.search(r"(?:^|/)(rhel|redhat|ubi)(\d+)?", lowered)
    if match:
        family = "ubi" if match.group(1) == "ubi" else "rhel"
        return family, match.group(2) or ""
    match = re.search(r"(?:^|/)(amazonlinux|amzn)[:@]?(\d+(?:\.\d+)?)", lowered)
    if match:
        return "amazonlinux", match.group(2)
    match = re.search(r"(?:^|/)(fedora)[:@]?(\d+)", lowered)
    if match:
        return "fedora", match.group(2)
    match = re.search(r"distroless/(?:base-)?debian(\d+)", lowered)
    if match:
        return "debian", match.group(1)
    return "", ""


def _is_slim(base: str) -> bool:
    lowered = base.lower()
    return any(
        marker in lowered for marker in ("slim", "alpine", "distroless", "scratch")
    )


def _slim_suggestions(base: str, family: str, slim: bool) -> list[str]:
    if not base:
        return [
            "paste image metadata (base_image or the OCI base.name label) for "
            "freshness checks"
        ]
    suggestions: list[str] = []
    if not slim:
        if family in ("debian", "ubuntu"):
            suggestions.append(
                "prefer a slim/minimal variant of the base image (for example "
                "debian:12-slim) to cut the runtime attack surface"
            )
        elif family in ("centos", "rhel", "ubi", "fedora", "amazonlinux"):
            suggestions.append(
                "prefer a minimal base (UBI micro/minimal or the slim variant) "
                "to cut the runtime attack surface"
            )
        suggestions.append(
            "use a multi-stage build and copy only runtime artifacts into the "
            "final image"
        )
        suggestions.append(
            "pin the base image by digest (name@sha256:...) so rebuilds are "
            "reproducible"
        )
    else:
        suggestions.append("keep the slim base current and rebuild regularly")
    if family not in ("alpine", "distroless", "") and not slim:
        suggestions.append(
            "consider alpine or distroless for a smaller runtime if the app is "
            "compatible"
        )
    return suggestions


def analyze_image(
    meta: dict[str, Any] | None,
    as_of: datetime | None = None,
    max_age_days: int = 365,
) -> dict[str, Any]:
    """Assess pasted image metadata for age, EOL and slimming options."""
    if not meta:
        return {}
    if not isinstance(meta, dict):
        raise ValueError("image metadata must be an object")
    now = as_of or datetime.now(tz=UTC)
    base = _image_base(meta)
    family, version = _image_family_version(base)
    created = _parse_dt(_image_created(meta))
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []

    age_days: int | None = None
    if created:
        age_days = max(0, (now - created).days)
    else:
        warnings.append("missing image creation timestamp")

    eol_text = ""
    eol_status = "unknown"
    if family and version:
        eol_text = BASE_EOL.get(family, {}).get(version, "")
        if eol_text:
            eol_date = _parse_dt(eol_text)
            if eol_date:
                if now.date() > eol_date.date():
                    eol_status = "expired"
                elif (
                    now.date()
                    >= (eol_date - timedelta(days=EOL_APPROACHING_DAYS)).date()
                ):
                    eol_status = "approaching"
                else:
                    eol_status = "supported"
        else:
            warnings.append(f"no EOL entry for {family}:{version}")
    elif base:
        warnings.append("could not identify base image family/version")

    stale = age_days is not None and age_days > max_age_days
    slim = _is_slim(base)

    if eol_status == "expired":
        findings.append(
            {
                "kind": "eol",
                "severity": "HIGH",
                "title": f"base image {family}:{version} is end-of-life",
                "detail": (
                    f"EOL date {eol_text}; rebuild on a supported base and "
                    "re-pull security updates"
                ),
            }
        )
    elif eol_status == "approaching":
        findings.append(
            {
                "kind": "eol_soon",
                "severity": "MEDIUM",
                "title": f"base image {family}:{version} approaches end-of-life",
                "detail": f"EOL date {eol_text}; plan the base-image upgrade",
            }
        )
    if stale and eol_status != "expired":
        findings.append(
            {
                "kind": "stale",
                "severity": "MEDIUM",
                "title": f"base image is {age_days} days old",
                "detail": (
                    f"older than the {max_age_days}-day freshness budget; rebuild "
                    "from a current base"
                ),
            }
        )

    return {
        "base": base,
        "family": family,
        "version": version,
        "created": created.isoformat() if created else "",
        "age_days": age_days,
        "max_age_days": max_age_days,
        "eol": eol_text,
        "eol_status": eol_status,
        "stale": stale,
        "slim": slim,
        "suggestions": _slim_suggestions(base, family, slim),
        "warnings": warnings,
        "findings": findings,
    }


def analyze(
    packages: list[Any] | None = None,
    inventory: str = "",
    image: dict[str, Any] | None = None,
    fmt: str = "auto",
    as_of: str | None = None,
    max_age_days: int = 365,
) -> dict[str, Any]:
    """Audit OS packages and base-image freshness from pasted, offline input."""
    if packages is not None and not isinstance(packages, list):
        raise ValueError("packages must be a list")
    package_entries = list(packages or [])
    if fmt not in VALID_FORMATS:
        raise ValueError("format must be auto, dpkg, rpm, apk or generic")
    if max_age_days < 0:
        raise ValueError("max_age_days must be non-negative")
    parsed: list[dict[str, str]] = []
    if inventory.strip():
        parsed.extend(parse_inventory(inventory, fmt))
    for entry in package_entries:
        parsed.append(_normalize_entry(entry, fmt))
    if not parsed and not image:
        raise ValueError("packages, inventory or image required")

    # Drop exact duplicates while keeping first-seen order.
    unique: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in parsed:
        normalized = _package_entry(entry, fmt)
        key = (
            normalized["name"],
            normalized["version"],
            normalized["ecosystem"],
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(normalized)

    verdicts = [_package_verdict(package) for package in unique]
    findings: list[dict[str, Any]] = []
    for package in unique:
        for advisory in _matching_advisories(package):
            if _advisory_status(package, advisory) == "vulnerable":
                findings.append(_finding(package, advisory))

    detected = sorted({p["ecosystem"] for p in unique if p["ecosystem"]})
    detected_format = (
        fmt
        if fmt != "auto"
        else ("mixed" if len(detected) > 1 else (detected[0] if detected else ""))
    )
    as_of_dt = None
    if as_of:
        as_of_dt = _parse_dt(as_of)
        if as_of_dt is None:
            raise ValueError("invalid as_of timestamp")
    image_result = analyze_image(image, as_of_dt, max_age_days) if image else {}

    return {
        "package_count": len(unique),
        "format": detected_format,
        "ecosystems": detected,
        "advisory_count": len(ADVISORIES),
        "vulnerable_count": len(findings),
        "fixed_count": sum(v["status"] == "fixed" for v in verdicts),
        "unknown_count": sum(v["status"] == "unknown" for v in verdicts),
        "packages": verdicts,
        "findings": findings,
        "image": image_result,
        "image_findings": len(image_result.get("findings") or []),
        "limitations": LIMITATIONS,
        "sandbox": False,
    }


def to_ledger(host: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    """Map vulnerable packages and image freshness gaps to engagement rows."""
    rows: list[dict[str, Any]] = []
    for finding in result.get("findings") or []:
        rows.append(
            {
                "host": host,
                "name": (
                    f"{finding.get('cve', '?')} {finding.get('package', '?')} "
                    f"{finding.get('version', '')}"
                )[:220].strip(),
                "severity": str(finding.get("severity") or "MEDIUM").upper(),
                "module": "os-package",
                "reference": str(finding.get("cve") or ""),
                "cwe": "CWE-1395",
                "detail": (
                    f"ecosystem={finding.get('ecosystem', '')} "
                    f"fixed={finding.get('fixed', '')} "
                    f"cvss={finding.get('cvss', '')} "
                    f"{finding.get('summary', '')}"
                ).strip()[:400],
            }
        )
    image = result.get("image") or {}
    for finding in image.get("findings") or []:
        rows.append(
            {
                "host": host,
                "name": str(finding.get("title") or "base image finding")[:220],
                "severity": str(finding.get("severity") or "MEDIUM").upper(),
                "module": "base-image",
                "reference": str(image.get("base") or ""),
                "cwe": "CWE-1104",
                "detail": (
                    f"kind={finding.get('kind', '')} "
                    f"eol={image.get('eol', '')} "
                    f"age_days={image.get('age_days', '')} "
                    f"{finding.get('detail', '')}"
                ).strip()[:400],
            }
        )
    return rows


def sandbox_result() -> dict[str, Any]:
    """Canned OS package + base-image result for sandbox mode."""
    result = analyze(
        packages=[
            {"name": "sudo", "version": "1.8.31", "ecosystem": "dpkg"},
            {"name": "zlib1g", "version": "1.2.11", "ecosystem": "dpkg"},
            {"name": "bash", "version": "5.1-6ubuntu1", "ecosystem": "dpkg"},
            {"name": "curl", "version": "7.81.0", "ecosystem": "dpkg"},
        ],
        image={"base_image": "debian:10-slim", "Created": "2021-01-01T00:00:00Z"},
        as_of="2026-11-27",
        max_age_days=365,
    )
    result["sandbox"] = True
    return result
