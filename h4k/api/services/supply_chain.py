"""Typosquat heuristics + SLSA/build-info provenance ingest (Backlog #68).

Offline supply-chain signals for software you are entitled to analyze:

* **Typosquat heuristics** compare declared package names against a small
  curated popular-package list per ecosystem. Edit distance, homoglyph
  substitutions, separator/combosquat patterns and unfamiliar npm scopes raise
  a review lead with a score and the matched target.
* **Provenance ingest** reads SLSA provenance (v1 / v0.2 / v0.1) and in-toto
  statements, plus plain build-info records, and reports whether the build
  identity, subject digest, source pinning and materials are present.

Both are deliberately honest. Nothing here talks to a registry, downloads an
attestation, shells out, or verifies a signature — a signal is a lead for a
human, not proof of malice, and a provenance record being "complete" only means
the expected fields are structurally present. Sandbox mode returns canned data
without parsing the request at all.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("h4k.supply_chain")

LIMITATIONS = (
    "Offline heuristics only: names are compared against a small curated "
    "popular-package list (edit distance, homoglyph, separator and combosquat "
    "patterns) and provenance is checked structurally (recognized SLSA/in-toto "
    "predicate, builder, subject digest, source pinning, materials). Signatures "
    "are NOT verified and no registry is contacted; treat every signal as a "
    "review lead, not proof of malice."
)

# Curated popular names used only as comparison targets. Kept small and stable
# so results are deterministic and do not depend on a network snapshot.
POPULAR: dict[str, tuple[str, ...]] = {
    "pypi": (
        "aiohttp",
        "attrs",
        "boto3",
        "certifi",
        "charset-normalizer",
        "click",
        "cryptography",
        "django",
        "fastapi",
        "flask",
        "idna",
        "jinja2",
        "matplotlib",
        "numpy",
        "packaging",
        "pandas",
        "pillow",
        "pip",
        "pydantic",
        "pytest",
        "pyyaml",
        "requests",
        "scipy",
        "setuptools",
        "six",
        "sqlalchemy",
        "urllib3",
        "wheel",
    ),
    "npm": (
        "async",
        "axios",
        "babel",
        "bluebird",
        "chalk",
        "commander",
        "debug",
        "dotenv",
        "eslint",
        "express",
        "glob",
        "jquery",
        "jsonwebtoken",
        "lodash",
        "minimist",
        "mkdirp",
        "moment",
        "mongoose",
        "next",
        "node-fetch",
        "passport",
        "prettier",
        "react",
        "react-dom",
        "request",
        "rimraf",
        "semver",
        "socket.io",
        "tar",
        "typescript",
        "underscore",
        "uuid",
        "vue",
        "webpack",
        "ws",
        "yargs",
    ),
}

# Well-known legitimate variants and first-party scopes. Operators can extend
# this per call with the `allowlist` field; these only suppress the heuristic.
KNOWN_SAFE: frozenset[str] = frozenset(
    {
        "babel-loader",
        "bcryptjs",
        "body-parser",
        "cross-fetch",
        "css-loader",
        "django-cors-headers",
        "dotenv-expand",
        "express-session",
        "express-validator",
        "flask-cors",
        "flask-login",
        "flask-sqlalchemy",
        "jsonwebtoken",
        "lodash.clonedeep",
        "lodash.debounce",
        "lodash.get",
        "lodash.isequal",
        "lodash.merge",
        "lodash.set",
        "lodash.template",
        "next-auth",
        "passport-jwt",
        "passport-local",
        "pip-tools",
        "postcss-loader",
        "python-dateutil",
        "python-dotenv",
        "python-slugify",
        "react-dom",
        "react-native",
        "react-redux",
        "react-router",
        "react-scripts",
        "requests-oauthlib",
        "requests-toolbelt",
        "setuptools-scm",
        "socket.io-client",
        "socket.io-parser",
        "style-loader",
        "tailwindcss",
        "vue-router",
        "vuex",
        "webpack-cli",
        "webpack-dev-server",
    }
)

KNOWN_SCOPES: frozenset[str] = frozenset(
    {
        "angular",
        "apollo",
        "aws-sdk",
        "azure",
        "babel",
        "emotion",
        "eslint",
        "google-cloud",
        "graphql-tools",
        "jest",
        "mui",
        "nestjs",
        "octokit",
        "opentelemetry",
        "prisma",
        "radix-ui",
        "sentry",
        "storybook",
        "tanstack",
        "testing-library",
        "trpc",
        "types",
        "typescript-eslint",
        "vue",
    }
)

COMBOSQUAT_AFFIXES: frozenset[str] = frozenset(
    {
        "api",
        "cdn",
        "cli",
        "client",
        "core",
        "download",
        "free",
        "helper",
        "helpers",
        "install",
        "js",
        "lib",
        "libs",
        "node",
        "npm",
        "official",
        "package",
        "pkg",
        "plus",
        "pro",
        "py",
        "python",
        "secure",
        "security",
        "server",
        "setup",
        "sdk",
        "tool",
        "tools",
        "update",
        "util",
        "utils",
    }
)

# ASCII lookalikes and a small set of Unicode confusables. Used only to test
# whether a name collapses onto a popular target, never to rewrite input.
_ASCII_LOOKALIKES = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
}
_UNICODE_LOOKALIKES = {
    "\u0430": "a",  # Cyrillic a
    "\u0435": "e",  # Cyrillic e
    "\u043e": "o",  # Cyrillic o
    "\u0440": "p",  # Cyrillic p
    "\u0441": "c",  # Cyrillic c
    "\u0443": "y",  # Cyrillic y
    "\u0445": "x",  # Cyrillic x
    "\u0456": "i",  # Cyrillic i
    "\u0455": "s",  # Cyrillic s
    "\u0501": "d",  # Cyrillic d
    "\u0261": "g",  # Latin script g
    "\u03bf": "o",  # Greek omicron
    "\u03b1": "a",  # Greek alpha
    "\u03bd": "v",  # Greek nu
    "\u03c1": "p",  # Greek rho
    "\u03c4": "t",  # Greek tau
    "\u0458": "j",  # Cyrillic je
    "\u04bb": "h",  # Cyrillic shha
    "\u04cf": "l",  # Cyrillic palochka
}
_SEQUENCE_LOOKALIKES = (("rn", "m"), ("vv", "w"), ("cl", "d"))

_SEPARATORS_RE = re.compile(r"[-_.]")
_DIGITS_RE = re.compile(r"^\d+$")
_PURL_RE = re.compile(
    r"^pkg:(?P<eco>[^/]+)/(?P<name>.+?)(?:@(?P<version>[^?#]+))?(?:[?#].*)?$"
)

_SLSA_TYPES = {
    "https://slsa.dev/provenance/v1": "slsa-v1",
    "https://slsa.dev/provenance/v0.2": "slsa-v0.2",
    "https://slsa.dev/provenance/v0.1": "slsa-v0.1",
}

_SEVERITY_BY_SCORE = ((80, "HIGH"), (55, "MEDIUM"))


def _levenshtein(left: str, right: str) -> int:
    """Iterative edit distance with a single rolling row."""
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, lch in enumerate(left, 1):
        current = [i]
        for j, rch in enumerate(right, 1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            replace = previous[j - 1] + (lch != rch)
            current.append(min(insert, delete, replace))
        previous = current
    return previous[-1]


def _dehomoglyph(name: str) -> str:
    out = "".join(_UNICODE_LOOKALIKES.get(ch, ch) for ch in name)
    out = "".join(_ASCII_LOOKALIKES.get(ch, ch) for ch in out.lower())
    for source, target in _SEQUENCE_LOOKALIKES:
        out = out.replace(source, target)
    return out


def _popular_for(ecosystem: str) -> tuple[str, ...]:
    if ecosystem in POPULAR:
        return POPULAR[ecosystem]
    merged: set[str] = set()
    for names in POPULAR.values():
        merged.update(names)
    return tuple(sorted(merged))


def _severity(score: int) -> str:
    for threshold, label in _SEVERITY_BY_SCORE:
        if score >= threshold:
            return label
    return "LOW"


def _parse_package(entry: Any) -> dict[str, str]:
    if isinstance(entry, str):
        raw_name = entry.strip()
        ecosystem = ""
        version = ""
    elif isinstance(entry, dict):
        raw_name = str(entry.get("name") or entry.get("package") or "").strip()
        ecosystem = str(entry.get("ecosystem") or entry.get("type") or "").lower()
        version = str(entry.get("version") or "").strip()
    else:
        raise ValueError("package entries must be strings or objects")
    if not raw_name:
        raise ValueError("package name required")
    match = _PURL_RE.match(raw_name)
    if match:
        ecosystem = (match.group("eco") or ecosystem).lower()
        raw_name = match.group("name")
        version = version or (match.group("version") or "")
    return {
        "name": raw_name,
        "ecosystem": ecosystem,
        "version": version,
    }


def _signal(kind: str, target: str, score: int, detail: str) -> dict[str, Any]:
    return {"kind": kind, "target": target, "score": score, "detail": detail}


def _scope_and_bare(name: str) -> tuple[str, str]:
    lowered = name.strip().lower()
    if lowered.startswith("@") and "/" in lowered:
        scope, bare = lowered[1:].split("/", 1)
        return scope, bare
    return "", lowered


def _package_signals(
    name: str,
    ecosystem: str,
    allowlist: set[str],
) -> list[dict[str, Any]]:
    lowered = name.strip().lower()
    scope, bare = _scope_and_bare(lowered)
    if lowered in allowlist or bare in allowlist:
        return []
    if lowered in KNOWN_SAFE or bare in KNOWN_SAFE:
        return []

    pool = _popular_for(ecosystem)
    signals: list[dict[str, Any]] = []

    if scope and bare in pool and scope not in KNOWN_SCOPES:
        signals.append(
            _signal(
                "scope_confusion",
                bare,
                50,
                f"popular package '{bare}' is published under unfamiliar "
                f"scope '@{scope}'",
            )
        )

    if bare in pool:
        return signals

    if not bare:
        return signals

    # Unicode / ASCII homoglyph that collapses onto a popular target.
    dehom = _dehomoglyph(bare)
    for target in pool:
        if dehom == target and bare != target:
            signals.append(
                _signal(
                    "homoglyph",
                    target,
                    85,
                    f"'{name}' uses lookalike characters for '{target}'",
                )
            )
            break
    if any(ord(ch) > 127 for ch in bare) and not signals:
        signals.append(
            _signal(
                "non_ascii",
                bare,
                45,
                "package name contains non-ASCII characters",
            )
        )

    # Separator-only difference (e.g. python_dateutil vs python-dateutil).
    if not signals:
        compact = _SEPARATORS_RE.sub("", bare)
        for target in pool:
            if bare == target:
                continue
            if compact == _SEPARATORS_RE.sub("", target):
                signals.append(
                    _signal(
                        "separator_confusion",
                        target,
                        45,
                        f"'{name}' differs from '{target}' only by separators",
                    )
                )
                break

    # Combosquat: popular name wrapped in a suspicious affix or trailing digits.
    if not signals:
        for target in pool:
            if target == bare or len(target) < 4:
                continue
            for affix in _combosquat_affixes(bare, target):
                if affix in COMBOSQUAT_AFFIXES or _DIGITS_RE.match(affix):
                    signals.append(
                        _signal(
                            "combosquat",
                            target,
                            60,
                            f"'{name}' wraps popular '{target}' with '{affix}'",
                        )
                    )
                    break
            if signals:
                break

    # Edit distance to a popular name (skip very short names to cut noise).
    if not signals and len(bare) >= 4:
        best: tuple[str, int] | None = None
        for target in pool:
            if target == bare or abs(len(target) - len(bare)) > 2:
                continue
            distance = _levenshtein(bare, target)
            threshold = 1 if len(target) < 6 else 2
            if 0 < distance <= threshold and (best is None or distance < best[1]):
                best = (target, distance)
        if best is not None:
            signals.append(
                _signal(
                    "typosquat",
                    best[0],
                    80,
                    f"'{name}' is edit distance {best[1]} from '{best[0]}'",
                )
            )

    return signals


def _combosquat_affixes(bare: str, target: str) -> list[str]:
    affixes: list[str] = []
    if bare.startswith(target):
        affixes.append(_SEPARATORS_RE.sub("", bare[len(target) :]))
    if bare.endswith(target):
        affixes.append(_SEPARATORS_RE.sub("", bare[: -len(target)]))
    return [affix for affix in affixes if affix]


def _package_verdict(
    entry: dict[str, str],
    allowlist: set[str],
) -> dict[str, Any]:
    signals = _package_signals(entry["name"], entry["ecosystem"], allowlist)
    score = 0
    if signals:
        score = min(100, max(s["score"] for s in signals) + 5 * (len(signals) - 1))
    return {
        "name": entry["name"],
        "ecosystem": entry["ecosystem"],
        "version": entry["version"],
        "verdict": "suspicious" if signals else "ok",
        "score": score,
        "severity": _severity(score) if signals else "",
        "signals": signals,
    }


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _nested(obj: Any, *keys: str) -> Any:
    current: Any = obj
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _builder_id(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return str(value.get("id") or value.get("uri") or "").strip()
    return ""


def _subject_list(record: dict[str, Any]) -> list[dict[str, Any]]:
    raw = record.get("subject") or record.get("subjects") or []
    if isinstance(raw, dict):
        return [raw]
    return [item for item in _as_list(raw) if isinstance(item, dict)]


def _digest_text(digest: Any) -> str:
    if isinstance(digest, str):
        return digest.strip()
    if isinstance(digest, dict):
        for algorithm in ("sha256", "sha512", "sha1", "gitCommit", "gitTree"):
            value = digest.get(algorithm)
            if value:
                return f"{algorithm}:{value}"
        for algorithm, value in sorted(digest.items()):
            if value:
                return f"{algorithm}:{value}"
    return ""


def _material_list(value: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for item in _as_list(value):
        if isinstance(item, str):
            out.append({"uri": item.strip(), "digest": ""})
        elif isinstance(item, dict):
            out.append(
                {
                    "uri": str(item.get("uri") or item.get("url") or "").strip(),
                    "digest": _digest_text(item.get("digest")),
                }
            )
    return out


def _source_pinned(source: str, materials: list[dict[str, str]]) -> bool:
    if any(material.get("digest") for material in materials):
        return True
    return any(marker in source for marker in ("@", "#", "?sha=", "?ref="))


def _provenance_record(record: dict[str, Any]) -> dict[str, Any]:
    statement_type = str(record.get("_type") or record.get("type") or "").strip()
    predicate_type = str(
        record.get("predicateType") or record.get("predicate_type") or ""
    ).strip()
    predicate = _as_dict(record.get("predicate"))

    if predicate_type in _SLSA_TYPES:
        flavor = _SLSA_TYPES[predicate_type]
    elif "slsa.dev/provenance" in predicate_type:
        flavor = "slsa"
    elif "in-toto.io/Statement" in statement_type:
        flavor = "in-toto"
    elif any(
        key in record for key in ("buildDefinition", "builder", "materials", "source")
    ):
        flavor = "build-info"
    else:
        flavor = "unknown"

    builder = ""
    source = ""
    materials: list[dict[str, str]] = []
    if flavor == "slsa-v1":
        builder = _builder_id(
            _nested(predicate, "buildDefinition", "builder")
            or _nested(predicate, "runDetails", "builder")
        )
        source = str(
            _nested(predicate, "buildDefinition", "externalParameters", "source", "uri")
            or ""
        ).strip()
        materials = _material_list(
            _nested(predicate, "buildDefinition", "resolvedDependencies")
        )
    elif flavor in ("slsa-v0.2", "slsa-v0.1", "slsa"):
        builder = _builder_id(predicate.get("builder"))
        source = str(
            _nested(predicate, "invocation", "configSource", "uri") or ""
        ).strip()
        materials = _material_list(predicate.get("materials"))
    elif flavor == "in-toto":
        builder = _builder_id(
            predicate.get("builder") or _nested(predicate, "runDetails", "builder")
        )
        source = str(
            _nested(predicate, "invocation", "configSource", "uri") or ""
        ).strip()
        materials = _material_list(predicate.get("materials"))
    elif flavor == "build-info":
        builder = _builder_id(record.get("builder"))
        source = str(
            record.get("source")
            or record.get("source_uri")
            or record.get("repository")
            or ""
        ).strip()
        materials = _material_list(record.get("materials"))
    if not source:
        source = str(_nested(record, "source", "uri") or "").strip()

    subjects = _subject_list(record)
    subject = subjects[0] if subjects else {}
    subject_name = str(
        subject.get("name")
        or subject.get("package")
        or record.get("package")
        or record.get("name")
        or ""
    ).strip()
    subject_digest = _digest_text(subject.get("digest")) or _digest_text(
        record.get("digest")
    )
    package = str(record.get("package") or subject_name or "<unknown>").strip()
    version = str(record.get("version") or "").strip()
    if not version and "@" in subject_name:
        version = subject_name.rsplit("@", 1)[-1]

    warnings: list[str] = []
    if flavor == "unknown":
        warnings.append("unrecognized provenance format")
    elif predicate_type and predicate_type not in _SLSA_TYPES:
        warnings.append("unrecognized SLSA predicate type")
    if not builder:
        warnings.append("missing builder identity")
    elif any(token in builder for token in ("localhost", "127.0.0.1", "file://")):
        warnings.append("builder identity is local/loopback")
    if not subject_name:
        warnings.append("missing subject")
    if not subject_digest:
        warnings.append("subject has no digest")
    if not source:
        warnings.append("missing source uri")
    elif not _source_pinned(source, materials):
        warnings.append("source is not pinned to a commit/digest")
    if not materials:
        warnings.append("no resolved materials")

    score = 0
    if flavor != "unknown":
        score += 10
    if builder:
        score += 25
    if subject_digest:
        score += 25
    if source:
        score += 15
    if source and _source_pinned(source, materials):
        score += 15
    if materials:
        score += 10

    if flavor == "unknown":
        status = "unknown"
    elif builder and subject_digest and source and _source_pinned(source, materials):
        status = "complete"
    else:
        status = "partial"

    return {
        "package": package,
        "version": version,
        "flavor": flavor,
        "predicate_type": predicate_type,
        "subject": subject_name,
        "digest": subject_digest,
        "builder": builder,
        "source": source,
        "pinned": bool(source and _source_pinned(source, materials)),
        "materials": len(materials),
        "status": status,
        "score": score,
        "warnings": warnings,
    }


def analyze(
    packages: list[Any] | None = None,
    provenance: list[Any] | None = None,
    allowlist: list[str] | None = None,
) -> dict[str, Any]:
    """Run typosquat heuristics and provenance ingest over supplied records."""
    package_entries = packages or []
    provenance_entries = provenance or []
    if not package_entries and not provenance_entries:
        raise ValueError("packages or provenance required")
    if not isinstance(package_entries, list):
        raise ValueError("packages must be a list")
    if not isinstance(provenance_entries, list):
        raise ValueError("provenance must be a list")
    allowed = {
        str(name).strip().lower() for name in (allowlist or []) if str(name).strip()
    }

    verdicts: list[dict[str, Any]] = []
    for entry in package_entries:
        verdicts.append(_package_verdict(_parse_package(entry), allowed))
    typosquats = [verdict for verdict in verdicts if verdict["verdict"] == "suspicious"]

    records: list[dict[str, Any]] = []
    for entry in provenance_entries:
        if not isinstance(entry, dict):
            raise ValueError("provenance entries must be objects")
        records.append(_provenance_record(entry))

    return {
        "package_count": len(verdicts),
        "suspicious_count": len(typosquats),
        "packages": verdicts,
        "typosquats": typosquats,
        "provenance_count": len(records),
        "provenance_complete": sum(r["status"] == "complete" for r in records),
        "provenance_partial": sum(r["status"] == "partial" for r in records),
        "provenance_unknown": sum(r["status"] == "unknown" for r in records),
        "provenance": records,
        "limitations": LIMITATIONS,
        "sandbox": False,
    }


def to_ledger(host: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    """Map suspicious packages and provenance gaps to engagement vuln rows."""
    rows: list[dict[str, Any]] = []
    for verdict in result.get("typosquats") or []:
        signals = verdict.get("signals") or []
        kinds = ", ".join(sorted({str(s.get("kind") or "") for s in signals}))
        targets = ", ".join(sorted({str(s.get("target") or "") for s in signals}))
        rows.append(
            {
                "host": host,
                "name": f"typosquat {verdict.get('name', '?')} ~ {targets}"[:220],
                "severity": str(verdict.get("severity") or "MEDIUM").upper(),
                "module": "typosquat",
                "reference": targets,
                "cwe": "CWE-1357",
                "detail": (
                    f"kinds={kinds} score={verdict.get('score', 0)} "
                    + " | ".join(str(s.get("detail") or "") for s in signals)
                ).strip()[:400],
            }
        )
    for record in result.get("provenance") or []:
        status = str(record.get("status") or "unknown")
        if status == "complete":
            continue
        package = str(record.get("package") or "<unknown>")
        rows.append(
            {
                "host": host,
                "name": f"provenance {package} ({status})"[:220],
                "severity": "MEDIUM" if status == "partial" else "LOW",
                "module": "provenance",
                "reference": str(record.get("source") or ""),
                "cwe": "CWE-1357",
                "detail": (
                    f"flavor={record.get('flavor', '')} "
                    f"score={record.get('score', 0)} warnings="
                    + ", ".join(str(w) for w in record.get("warnings") or [])
                ).strip()[:400],
            }
        )
    return rows


def sandbox_result() -> dict[str, Any]:
    """Canned typosquat + provenance result for sandbox mode."""
    result = analyze(
        packages=[
            {"name": "requests", "ecosystem": "pypi"},
            {"name": "reqeusts", "ecosystem": "pypi"},
            {"name": "@evil/lodash", "ecosystem": "npm"},
            {"name": "react", "ecosystem": "npm"},
        ],
        provenance=[
            {
                "_type": "https://in-toto.io/Statement/v1",
                "subject": [
                    {
                        "name": "pkg:npm/acme-app@1.2.3",
                        "digest": {"sha256": "a" * 64},
                    }
                ],
                "predicateType": "https://slsa.dev/provenance/v1",
                "predicate": {
                    "buildDefinition": {
                        "buildType": "https://slsa.dev/github-actions-workflow@v1",
                        "externalParameters": {
                            "source": {
                                "uri": "git+https://github.com/acme/app@refs/heads/main"
                            }
                        },
                        "resolvedDependencies": [
                            {
                                "uri": "git+https://github.com/acme/app@abc123",
                                "digest": {"gitCommit": "abc123"},
                            }
                        ],
                    },
                    "runDetails": {
                        "builder": {"id": "https://github.com/actions/runner"}
                    },
                },
            },
            {
                "_type": "https://in-toto.io/Statement/v0.1",
                "subject": [
                    {
                        "name": "pkg:pypi/acme-lib@0.9.0",
                        "digest": {"sha256": "b" * 64},
                    }
                ],
                "predicateType": "https://slsa.dev/provenance/v0.2",
                "predicate": {
                    "builder": {"id": "https://localhost/builder"},
                    "materials": [],
                },
            },
            {
                "package": "mystery-wheel",
                "version": "1.0.0",
                "note": "no attestation supplied (sandbox)",
            },
        ],
    )
    result["sandbox"] = True
    return result
