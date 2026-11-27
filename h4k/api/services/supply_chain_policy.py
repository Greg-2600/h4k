"""Supply-chain policy: license gate + SBOM diff + pin bot (Backlog #69).

Offline policy checks over dependency/SBOM lists the operator pastes:

* **License gate** classifies each declared license expression against a
  built-in deny/warn policy plus operator overrides. SPDX ``OR`` means the
  operator may choose a branch, so the best branch wins; ``AND`` means every
  obligation applies, so the worst branch wins. Unknown/missing licenses warn.
* **SBOM diff** compares a baseline and a current dependency list, reporting
  new/removed packages, version changes (upgrade/downgrade where the supplied
  versions are comparable) and CVEs introduced or resolved between the two.
* **Pin bot** only *suggests* exact pins for floating ranges and newer supplied
  versions (including a CVE's ``fixed_version``). It never edits a manifest,
  resolves a registry version, or installs anything.

Nothing here contacts a registry, downloads an SBOM, shells out, or writes a
file. Version comparison is a small semver-ish helper and is reported as
``changed`` when the supplied strings cannot be ordered. Sandbox mode returns a
canned result without parsing the request.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.supply_chain_policy")

LIMITATIONS = (
    "Offline policy only: licenses are matched against a built-in deny/warn "
    "list plus operator overrides, and diff/pin decisions use only the "
    "dependency records supplied in the request. No registry, advisory feed, "
    "manifest or lockfile is contacted or modified, and the pin bot only "
    "suggests versions the caller already supplied. A version that cannot be "
    "ordered is reported as changed, not upgraded/downgraded."
)

# Strong-copyleft / non-commercial / source-available licenses that usually
# conflict with proprietary distribution. Extend per call with deny_licenses.
DEFAULT_DENY_LICENSES: tuple[str, ...] = (
    "agpl-3.0",
    "agpl-3.0-only",
    "agpl-3.0-or-later",
    "busl-1.1",
    "cc-by-nc-4.0",
    "cc-by-nc-sa-4.0",
    "elastic-2.0",
    "gpl-3.0",
    "gpl-3.0-only",
    "gpl-3.0-or-later",
    "sspl-1.0",
)

# Notice / weak-copyleft / file-level obligations that deserve a review rather
# than an outright deny. Extend per call with warn_licenses.
DEFAULT_WARN_LICENSES: tuple[str, ...] = (
    "artistic-2.0",
    "cc-by-4.0",
    "cc-by-sa-4.0",
    "cddl-1.0",
    "cddl-1.1",
    "cpl-1.0",
    "epl-1.0",
    "epl-2.0",
    "eupl-1.2",
    "gpl-2.0",
    "gpl-2.0-only",
    "gpl-2.0-or-later",
    "lgpl-2.0",
    "lgpl-2.0-only",
    "lgpl-2.0-or-later",
    "lgpl-2.1",
    "lgpl-2.1-only",
    "lgpl-2.1-or-later",
    "lgpl-3.0",
    "lgpl-3.0-only",
    "lgpl-3.0-or-later",
    "mpl-2.0",
    "osl-3.0",
)

# Common permissive licenses. Anything not recognized and not denied warns, so
# an unfamiliar license is a review lead rather than a silent pass.
DEFAULT_ALLOW_LICENSES: tuple[str, ...] = (
    "0bsd",
    "apache-2.0",
    "blueoak-1.0.0",
    "bsd-2-clause",
    "bsd-3-clause",
    "bsd-3-clause-clear",
    "cc0-1.0",
    "isc",
    "mit",
    "mit-0",
    "ms-pl",
    "postgresql",
    "psf-2.0",
    "python-2.0",
    "unlicense",
    "wtfpl",
    "x11",
    "zlib",
)

_LICENSE_ALIASES = {
    "apache 2": "apache-2.0",
    "apache 2.0": "apache-2.0",
    "apache-2.0 license": "apache-2.0",
    "apache license 2.0": "apache-2.0",
    "apache2": "apache-2.0",
    "bsd": "bsd-3-clause",
    "bsd-2": "bsd-2-clause",
    "bsd-3": "bsd-3-clause",
    "gpl-2": "gpl-2.0",
    "gpl-2.0+": "gpl-2.0-or-later",
    "gpl-3": "gpl-3.0",
    "gpl-3.0+": "gpl-3.0-or-later",
    "gplv2": "gpl-2.0",
    "gplv3": "gpl-3.0",
    "lgpl-2.1+": "lgpl-2.1-or-later",
    "lgpl-3.0+": "lgpl-3.0-or-later",
    "lgplv3": "lgpl-3.0",
    "mit license": "mit",
    "mpl-2": "mpl-2.0",
    "new bsd": "bsd-3-clause",
    "the unlicense": "unlicense",
}

_RANK = {"allowed": 0, "warn": 1, "denied": 2}
_UNKNOWN_LICENSES = frozenset({"", "none", "noassertion", "unknown", "unlicensed"})

_PURL_RE = re.compile(
    r"^pkg:(?P<eco>[^/]+)/(?P<name>.+?)(?:@(?P<version>[^?#]+))?(?:[?#].*)?$"
)
_FLOATING_RE = re.compile(r"[<>=^~*|,]|\bx\b|\s-\s|\s")


def _normalize_license(token: str) -> str:
    value = token.strip().strip("()").lower()
    value = re.sub(r"\s+", " ", value)
    return _LICENSE_ALIASES.get(value, value)


def _split_expression(expression: str, operator: str) -> list[str]:
    pattern = re.compile(rf"\s+{operator}\s+", re.IGNORECASE)
    return [part.strip() for part in pattern.split(expression) if part.strip()]


def _license_atom_verdict(
    atom: str,
    deny: set[str],
    warn: set[str],
    allow_custom: set[str],
) -> tuple[str, str, str]:
    base = re.split(r"\s+with\s+", atom, maxsplit=1, flags=re.IGNORECASE)[0]
    normalized = _normalize_license(base)
    if normalized in _UNKNOWN_LICENSES:
        return "warn", "no license declared or recognized", normalized
    if normalized in allow_custom:
        return "allowed", f"'{normalized}' is explicitly allowed", normalized
    if normalized in deny:
        return "denied", f"'{normalized}' is on the deny list", normalized
    if normalized in warn:
        return "warn", f"'{normalized}' is on the warn list", normalized
    if normalized in DEFAULT_ALLOW_LICENSES:
        return (
            "allowed",
            f"'{normalized}' is a recognized permissive license",
            normalized,
        )
    return "warn", f"'{normalized}' is not on the allowed list", normalized


def _license_verdict(
    expression: str,
    deny: set[str],
    warn: set[str],
    allow_custom: set[str],
) -> tuple[str, str, list[str]]:
    expr = (expression or "").strip()
    if not expr:
        return "warn", "no license declared", []
    options = _split_expression(expr, "or")
    evaluated: list[tuple[str, str, str]] = []
    matched: list[str] = []
    for option in options:
        atoms = _split_expression(option, "and")
        atom_results = [
            _license_atom_verdict(atom, deny, warn, allow_custom) for atom in atoms
        ]
        matched.extend(result[2] for result in atom_results if result[2])
        worst = max(atom_results, key=lambda result: _RANK[result[0]])
        evaluated.append(worst)
    best = min(evaluated, key=lambda result: _RANK[result[0]])
    return best[0], best[1], matched


def _license_text(entry: dict[str, Any]) -> str:
    for key in ("license", "licenses", "license_expression"):
        if key not in entry:
            continue
        value = entry[key]
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, dict):
            name = value.get("id") or value.get("name") or value.get("expression")
            return str(name).strip() if name else ""
        if isinstance(value, list):
            parts: list[str] = []
            for item in value:
                if isinstance(item, str):
                    parts.append(item.strip())
                elif isinstance(item, dict):
                    lic = (
                        item.get("license")
                        if isinstance(item.get("license"), dict)
                        else item
                    )
                    name = (
                        lic.get("id") or lic.get("name")
                        if isinstance(lic, dict)
                        else ""
                    )
                    if name:
                        parts.append(str(name).strip())
            return " AND ".join(part for part in parts if part)
    return ""


def _cve_list(entry: dict[str, Any]) -> list[dict[str, str]]:
    raw = (
        entry.get("cves")
        or entry.get("vulnerabilities")
        or entry.get("vulns")
        or entry.get("advisories")
        or []
    )
    if isinstance(raw, (str, dict)):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    out: list[dict[str, str]] = []
    for item in raw:
        if isinstance(item, str):
            cve_id = item.strip().upper()
            out.append({"id": cve_id, "severity": "", "fixed_version": ""})
        elif isinstance(item, dict):
            cve_id = (
                str(
                    item.get("id")
                    or item.get("cve")
                    or item.get("cve_id")
                    or item.get("name")
                    or ""
                )
                .strip()
                .upper()
            )
            out.append(
                {
                    "id": cve_id,
                    "severity": str(item.get("severity") or "").strip().upper(),
                    "fixed_version": str(
                        item.get("fixed_version")
                        or item.get("fixed")
                        or item.get("fix_version")
                        or ""
                    ).strip(),
                }
            )
    return [cve for cve in out if cve["id"]]


def _parse_dependency(entry: Any) -> dict[str, Any]:
    if isinstance(entry, str):
        raw = entry.strip()
        ecosystem = ""
        version = ""
        match = _PURL_RE.match(raw)
        if match:
            ecosystem = (match.group("eco") or "").lower()
            raw = match.group("name")
            version = match.group("version") or ""
        else:
            at = raw.rfind("@")
            if at > 0:
                raw, version = raw[:at], raw[at + 1 :]
        name = raw.strip()
        source: dict[str, Any] = {}
    elif isinstance(entry, dict):
        source = entry
        name = str(
            entry.get("name") or entry.get("package") or entry.get("component") or ""
        ).strip()
        ecosystem = str(entry.get("ecosystem") or entry.get("type") or "").lower()
        version = str(entry.get("version") or "").strip()
        purl = str(entry.get("purl") or "").strip()
        if purl:
            match = _PURL_RE.match(purl)
            if match:
                ecosystem = ecosystem or (match.group("eco") or "").lower()
                version = version or (match.group("version") or "")
                if not name:
                    name = match.group("name").strip()
    else:
        raise ValueError("dependency entries must be strings or objects")
    if not name:
        raise ValueError("dependency name required")

    latest = str(
        source.get("latest")
        or source.get("latest_version")
        or source.get("available")
        or ""
    ).strip()
    resolved = str(
        source.get("resolved") or source.get("installed") or source.get("locked") or ""
    ).strip()
    return {
        "key": name.lower(),
        "name": name,
        "ecosystem": ecosystem,
        "version": version,
        "license": _license_text(source) if source else "",
        "cves": _cve_list(source) if source else [],
        "latest": latest,
        "resolved": resolved,
        "floating": bool(_FLOATING_RE.search(version)),
    }


def _dependency_list(value: Any, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        if "components" not in value:
            raise ValueError(f"{label} must be a list or an SBOM object")
        value = value.get("components") or []
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list or an SBOM object")
    return [_parse_dependency(entry) for entry in value]


def _version_parts(value: str) -> tuple[tuple[int, ...], tuple[Any, ...]] | None:
    text = value.strip().lower()
    if not text or _FLOATING_RE.search(text):
        return None
    text = text.lstrip("v").split("+", 1)[0]
    main, _, prerelease = text.partition("-")
    main_parts: list[int] = []
    for part in main.split("."):
        if part.isdigit():
            main_parts.append(int(part))
            continue
        match = re.match(r"\d+", part)
        if match:
            main_parts.append(int(match.group(0)))
            continue
        return None
    pre_parts: list[tuple[int, Any]] = []
    for part in prerelease.split(".") if prerelease else []:
        if part.isdigit():
            pre_parts.append((0, int(part)))
        else:
            pre_parts.append((1, part))
    return tuple(main_parts), tuple(pre_parts)


def _compare_versions(left: str, right: str) -> int | None:
    left_parts = _version_parts(left)
    right_parts = _version_parts(right)
    if left_parts is None or right_parts is None:
        return None
    left_main, left_pre = left_parts
    right_main, right_pre = right_parts
    width = max(len(left_main), len(right_main))
    left_main = left_main + (0,) * (width - len(left_main))
    right_main = right_main + (0,) * (width - len(right_main))
    if left_main != right_main:
        return -1 if left_main < right_main else 1
    if not left_pre and right_pre:
        return 1
    if left_pre and not right_pre:
        return -1
    if left_pre != right_pre:
        return -1 if left_pre < right_pre else 1
    return 0


def _cve_row(dependency: dict[str, Any], cve: dict[str, str]) -> dict[str, str]:
    return {
        "package": dependency["name"],
        "ecosystem": dependency["ecosystem"],
        "version": dependency["version"],
        "cve": cve["id"],
        "severity": cve["severity"],
        "fixed_version": cve["fixed_version"],
    }


def _dep_row(dependency: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": dependency["name"],
        "ecosystem": dependency["ecosystem"],
        "version": dependency["version"],
        "license": dependency["license"],
        "cves": sorted({cve["id"] for cve in dependency["cves"]}),
    }


def _diff(
    baseline: list[dict[str, Any]], current: list[dict[str, Any]]
) -> dict[str, Any]:
    base = {dependency["key"]: dependency for dependency in baseline}
    cur = {dependency["key"]: dependency for dependency in current}
    new = [cur[key] for key in cur if key not in base]
    removed = [base[key] for key in base if key not in cur]
    changed: list[dict[str, Any]] = []
    new_cves: list[dict[str, str]] = []
    resolved_cves: list[dict[str, str]] = []

    for key in sorted(set(base) & set(cur)):
        before = base[key]
        after = cur[key]
        direction = ""
        if before["version"] != after["version"]:
            comparison = _compare_versions(after["version"], before["version"])
            if comparison is None:
                direction = "changed"
            elif comparison > 0:
                direction = "upgrade"
            elif comparison < 0:
                direction = "downgrade"
            else:
                direction = "changed"
        license_changed = _normalize_license(before["license"]) != _normalize_license(
            after["license"]
        )
        if direction or license_changed:
            changed.append(
                {
                    "name": after["name"],
                    "ecosystem": after["ecosystem"],
                    "from_version": before["version"],
                    "to_version": after["version"],
                    "direction": direction or "license",
                    "license_changed": license_changed,
                }
            )
        before_cves = {cve["id"] for cve in before["cves"]}
        after_cves = {cve["id"] for cve in after["cves"]}
        new_cves.extend(
            _cve_row(after, cve)
            for cve in after["cves"]
            if cve["id"] not in before_cves
        )
        resolved_cves.extend(
            _cve_row(before, cve)
            for cve in before["cves"]
            if cve["id"] not in after_cves
        )

    for dependency in new:
        new_cves.extend(_cve_row(dependency, cve) for cve in dependency["cves"])

    def _unique_cves(rows: list[dict[str, str]]) -> list[dict[str, str]]:
        seen: set[tuple[str, str]] = set()
        unique: list[dict[str, str]] = []
        for row in sorted(rows, key=lambda item: (item["package"], item["cve"])):
            key = (row["package"], row["cve"])
            if key not in seen:
                seen.add(key)
                unique.append(row)
        return unique

    return {
        "new": sorted((_dep_row(dep) for dep in new), key=lambda row: row["name"]),
        "removed": sorted(
            (_dep_row(dep) for dep in removed), key=lambda row: row["name"]
        ),
        "changed": sorted(changed, key=lambda row: row["name"]),
        "new_cves": _unique_cves(new_cves),
        "resolved_cves": _unique_cves(resolved_cves),
        "new_count": len(new),
        "removed_count": len(removed),
        "changed_count": len(changed),
    }


def _pin_string(name: str, version: str, ecosystem: str) -> str:
    if ecosystem.lower() in ("pypi", "pip", "python"):
        return f"{name}=={version}"
    return f"{name}@{version}"


def _pin_bot(
    current: list[dict[str, Any]], new_cves: list[dict[str, str]]
) -> list[dict[str, str]]:
    by_name = {dependency["key"]: dependency for dependency in current}
    suggestions: dict[tuple[str, str], dict[str, str]] = {}

    def _add(dependency: dict[str, Any], target: str, kind: str, reason: str) -> None:
        target = target.strip().lstrip("=").strip()
        if not target or target == dependency["version"]:
            return
        key = (dependency["name"].lower(), target)
        entry = suggestions.get(key)
        if entry is None:
            suggestions[key] = {
                "name": dependency["name"],
                "ecosystem": dependency["ecosystem"],
                "from": dependency["version"],
                "to": target,
                "kind": kind,
                "pinned": _pin_string(
                    dependency["name"], target, dependency["ecosystem"]
                ),
                "reason": reason,
            }
        elif reason not in entry["reason"].split("; "):
            entry["reason"] = f"{entry['reason']}; {reason}"

    for dependency in current:
        latest = dependency["latest"]
        if latest:
            comparison = _compare_versions(latest, dependency["version"])
            if comparison is not None and comparison > 0:
                _add(dependency, latest, "upgrade", "newer version supplied")
            elif dependency["floating"]:
                _add(
                    dependency,
                    latest,
                    "pin",
                    "replace a floating range with a pinned version",
                )
        if dependency["floating"] and dependency["resolved"]:
            _add(
                dependency,
                dependency["resolved"],
                "pin",
                "pin the resolved version instead of a floating range",
            )

    for cve in new_cves:
        fixed = cve.get("fixed_version") or ""
        target = by_name.get(cve["package"].lower())
        if fixed and target is not None:
            _add(
                target,
                fixed,
                "security",
                f"fix {cve['cve']}",
            )

    return sorted(suggestions.values(), key=lambda row: (row["name"], row["to"]))


def analyze(
    baseline: Any = None,
    current: Any = None,
    deny_licenses: list[str] | None = None,
    warn_licenses: list[str] | None = None,
    allow_licenses: list[str] | None = None,
) -> dict[str, Any]:
    """Run the license gate, SBOM diff and pin bot over supplied records."""
    base = _dependency_list(baseline, "baseline")
    cur = _dependency_list(current, "current")
    if not cur:
        raise ValueError("current dependencies required")

    deny = {_normalize_license(name) for name in DEFAULT_DENY_LICENSES}
    deny.update(_normalize_license(name) for name in (deny_licenses or []))
    warn = {_normalize_license(name) for name in DEFAULT_WARN_LICENSES}
    warn.update(_normalize_license(name) for name in (warn_licenses or []))
    allow_custom = {_normalize_license(name) for name in (allow_licenses or [])}

    verdicts: list[dict[str, Any]] = []
    counts = {"allowed": 0, "warn": 0, "denied": 0}
    for dependency in cur:
        verdict, reason, atoms = _license_verdict(
            dependency["license"], deny, warn, allow_custom
        )
        counts[verdict] += 1
        verdicts.append(
            {
                "name": dependency["name"],
                "ecosystem": dependency["ecosystem"],
                "version": dependency["version"],
                "license": dependency["license"],
                "verdict": verdict,
                "reason": reason,
                "matched": sorted(set(atoms)),
            }
        )

    diff = _diff(base, cur)
    pins = _pin_bot(cur, diff["new_cves"])
    return {
        "baseline_count": len(base),
        "current_count": len(cur),
        "policy": {"deny": sorted(deny), "warn": sorted(warn)},
        "license_counts": counts,
        "license_verdicts": verdicts,
        "denied": [row for row in verdicts if row["verdict"] == "denied"],
        "warned": [row for row in verdicts if row["verdict"] == "warn"],
        "diff": diff,
        "pin_bot": pins,
        "pin_count": len(pins),
        "limitations": LIMITATIONS,
        "sandbox": False,
    }


def to_ledger(host: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    """Map denied/warned licenses and newly introduced CVEs to vuln rows."""
    rows: list[dict[str, Any]] = []
    for verdict in result.get("denied") or []:
        rows.append(
            {
                "host": host,
                "name": (
                    f"license {verdict.get('license', '?')} on "
                    f"{verdict.get('name', '?')}"
                )[:220],
                "severity": "HIGH",
                "module": "license",
                "reference": str(verdict.get("license") or ""),
                "cwe": "CWE-1357",
                "detail": (
                    f"denied license {verdict.get('license', '')} "
                    f"({verdict.get('reason', '')})"
                )[:400],
            }
        )
    for verdict in result.get("warned") or []:
        rows.append(
            {
                "host": host,
                "name": (
                    f"license review {verdict.get('license') or 'unknown'} on "
                    f"{verdict.get('name', '?')}"
                )[:220],
                "severity": "LOW",
                "module": "license",
                "reference": str(verdict.get("license") or ""),
                "cwe": "CWE-1357",
                "detail": (
                    f"license needs review {verdict.get('license', '')} "
                    f"({verdict.get('reason', '')})"
                )[:400],
            }
        )
    for cve in (result.get("diff") or {}).get("new_cves") or []:
        fixed = cve.get("fixed_version") or ""
        rows.append(
            {
                "host": host,
                "name": (
                    f"new {cve.get('cve', '?')} in "
                    f"{cve.get('package', '?')}@{cve.get('version', '?')}"
                )[:220],
                "severity": str(cve.get("severity") or "MEDIUM").upper(),
                "module": "sbom-diff",
                "reference": str(cve.get("cve") or ""),
                "cwe": "CWE-1104",
                "detail": (
                    f"introduced since baseline; fixed_version={fixed or 'unknown'}"
                )[:400],
            }
        )
    return rows


def sandbox_result() -> dict[str, Any]:
    """Canned license/diff/pin result for sandbox mode."""
    result = analyze(
        baseline=[
            {"name": "lodash", "ecosystem": "npm", "version": "4.17.20"},
            {"name": "left-pad", "ecosystem": "npm", "version": "1.3.0"},
            {
                "name": "gpl-tool",
                "ecosystem": "pypi",
                "version": "1.0.0",
                "license": "GPL-3.0-only",
            },
        ],
        current=[
            {
                "name": "lodash",
                "ecosystem": "npm",
                "version": "4.17.20",
                "license": "MIT",
                "latest": "4.17.21",
                "cves": [
                    {
                        "id": "CVE-2021-23337",
                        "severity": "HIGH",
                        "fixed_version": "4.17.21",
                    }
                ],
            },
            {
                "name": "gpl-tool",
                "ecosystem": "pypi",
                "version": "1.0.0",
                "license": "GPL-3.0-only",
            },
            {
                "name": "notice-lib",
                "ecosystem": "npm",
                "version": "2.0.0",
                "license": "MPL-2.0",
            },
            {
                "name": "mystery-lib",
                "ecosystem": "pypi",
                "version": "0.1.0",
            },
            {
                "name": "new-http",
                "ecosystem": "npm",
                "version": "^3.0.0",
                "license": "Apache-2.0",
                "resolved": "3.0.2",
            },
        ],
    )
    result["sandbox"] = True
    return result
