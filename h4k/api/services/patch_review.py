"""AI-style patch ranking, test generation and false-positive judge (Backlog #74).

The offline, deterministic half of the AI review loop:

* **Patch ranking** scores operator-supplied patch candidates against the
  reported CWE with transparent heuristics (does it use a bound query, an
  argv array, output encoding, bounds checks, a safe parser, ...), penalises
  anti-patterns (``shell=True``, ``eval``, disabled TLS verification, scanner
  suppressions) and returns ranked candidates with explicit tradeoffs. When
  no candidates are supplied it returns three deterministic direction
  templates so a demo still has something to compare.
* **Test generation** builds a regression-test skeleton for the reported
  weakness in Python/pytest, JavaScript/Jest or Go/testing (generic steps
  otherwise), including safe marker payloads and negative variants.
* **False-positive judge** weighs operator-supplied evidence (reachability,
  input flow, sanitizer, affected version, runtime confirmation, compensating
  control) into a verdict. It is deliberately conservative: a finding is only
  cleared when positive evidence supports that, never from missing data.

Nothing here calls a model, contacts the network, runs a tool or executes a
candidate. The "AI" is a deterministic reviewer that is useful without an API
key and reproducible in CI. Sandbox mode returns canned data.
"""

from __future__ import annotations

import re
from typing import Any

LIMITATIONS = (
    "Offline, deterministic review assist only: patch ranking and the "
    "false-positive judge are transparent text/evidence heuristics, not a "
    "language model, and generated tests are skeletons that must be adapted "
    "to the real entry point. The judge only clears a finding when positive "
    "evidence (no reachable path, input cannot reach the sink, a sanitizer, "
    "an unaffected version or a compensating control) supports it; missing "
    "evidence stays needs_review. Nothing is executed, fetched or persisted "
    "beyond the optional scope-checked ledger row for a confirmed finding."
)

MAX_PATCHES = 25
MAX_TEXT = 40000

_CWE_RE = re.compile(r"(?:CWE[-_ ]?)?(\d{1,5})", re.IGNORECASE)
_SLUG_RE = re.compile(r"[^a-z0-9]+")

_CWE_FAMILY = {
    "77": "injection",
    "78": "injection",
    "89": "injection",
    "94": "injection",
    "95": "injection",
    "943": "injection",
    "79": "xss",
    "80": "xss",
    "22": "path",
    "23": "path",
    "36": "path",
    "119": "memory",
    "120": "memory",
    "121": "memory",
    "122": "memory",
    "125": "memory",
    "190": "memory",
    "416": "memory",
    "787": "memory",
    "502": "deserialization",
    "611": "deserialization",
    "918": "ssrf",
    "441": "ssrf",
    "269": "auth",
    "287": "auth",
    "306": "auth",
    "862": "auth",
    "863": "auth",
    "200": "info",
    "209": "info",
    "532": "info",
}

_FAMILY_CONTROLS: dict[str, tuple[tuple[str, str, int], ...]] = {
    "injection": (
        (
            r"\b(?:parameteri[sz]ed|prepared statement|bind_param|bindparam|"
            r"placeholder)\b",
            "uses a parameterized query/statement",
            14,
        ),
        (r"(?:%s|\?|:\w+|\$\d+)", "uses bound placeholders", 10),
        (
            r"\b(?:allowlist|whitelist|safe list)\b",
            "validates against an allowlist",
            8,
        ),
        (
            r"\b(?:shlex\.quote|escape|sanitiz|encode)\w*",
            "escapes or sanitizes input",
            8,
        ),
        (
            r"\b(?:subprocess\.(?:run|call|check_output))\s*\(\s*\[",
            "uses an argv-style command",
            12,
        ),
        (r"\bshell\s*=\s*false\b", "explicitly disables the shell", 10),
    ),
    "xss": (
        (
            r"\b(?:escape|encode|sanitiz|autoescape|textContent|text_content)\w*",
            "encodes or sanitizes output",
            14,
        ),
        (
            r"\b(?:allowlist|whitelist|bleach|dompurify|markupsafe)\b",
            "uses a vetted sanitizer or allowlist",
            12,
        ),
        (r"\b(?:Content-Security-Policy|csp)\b", "adds a CSP control", 8),
    ),
    "path": (
        (
            r"\b(?:realpath|resolve|normalize|canonicali[sz]e|abspath)\w*",
            "canonicalizes the path",
            14,
        ),
        (
            r"\b(?:startswith|is_relative_to|commonpath|base_dir|allowed_root)\b",
            "confines the path to a base directory",
            14,
        ),
        (
            r"\b(?:allowlist|whitelist|safe list)\b",
            "validates against an allowlist",
            8,
        ),
    ),
    "memory": (
        (
            r"\b(?:snprintf|strlcpy|strlcat|memcpy_s|strncpy_s|g_strlcpy)\b",
            "uses a bounds-checked copy",
            16,
        ),
        (
            r"\b(?:sizeof|length|len\b|size_t|capacity|bounds)\b",
            "checks the buffer length",
            12,
        ),
        (
            r"\b(?:std::vector|std::string|span|slice|safe container)\b",
            "uses a memory-safe container",
            10,
        ),
    ),
    "deserialization": (
        (
            r"\b(?:safe_load|safe_loader|SafeLoader|allowlist|allowed_classes)\b",
            "uses a safe loader/allowlist",
            16,
        ),
        (
            r"\b(?:signature|signed|hmac|verify|integrity)\w*",
            "verifies integrity/signature",
            12,
        ),
        (
            r"\b(?:json\.loads|parse_json|from_json)\b",
            "uses a data-only parser",
            8,
        ),
    ),
    "ssrf": (
        (
            r"\b(?:allowlist|whitelist|allowed_hosts|allowed_domains)\b",
            "validates the destination allowlist",
            16,
        ),
        (
            r"\b(?:ipaddress|private|loopback|link_local|is_global|resolve)\b",
            "rejects private/link-local destinations",
            12,
        ),
        (r"\b(?:https?|urlparse|urlsplit)\b", "parses and constrains the URL", 6),
    ),
    "auth": (
        (
            r"\b(?:authoriz|permission|least privilege|require_login|"
            r"authenticated)\w*",
            "enforces authentication/authorization",
            16,
        ),
        (
            r"\b(?:fail closed|deny by default|return false|raise (?:Permission|"
            r"Auth)\w*)\b",
            "fails closed",
            12,
        ),
        (
            r"\b(?:server.side|re-?check|verify (?:role|permission))\b",
            "re-checks authorization server-side",
            10,
        ),
    ),
    "info": (
        (
            r"\b(?:redact|mask|minimi[sz]e|filter|omit)\w*",
            "redacts or minimizes exposed data",
            14,
        ),
        (
            r"\b(?:authoriz|permission|require_login|authenticated)\w*",
            "enforces authorization on the response",
            12,
        ),
        (
            r"\b(?:generic error|safe error|no stack trace|log only)\b",
            "avoids verbose error leakage",
            8,
        ),
    ),
    "generic": (
        (
            r"\b(?:validate|validation|allowlist|whitelist)\w*",
            "adds input validation",
            10,
        ),
        (
            r"\b(?:sanitiz|escape|encode|parameteri[sz]|quote)\w*",
            "uses safe handling",
            10,
        ),
        (
            r"\b(?:authoriz|permission|least privilege|fail closed)\w*",
            "adds an authorization/containment control",
            8,
        ),
    ),
}

_ANTI_PATTERNS: tuple[tuple[str, str, int], ...] = (
    (r"shell\s*=\s*true", "keeps shell=True", 20),
    (r"\bos\.system\s*\(", "uses os.system", 15),
    (r"\beval\s*\(", "introduces eval", 18),
    (r"\bexec\s*\(", "introduces exec", 12),
    (r"verify\s*=\s*false", "disables TLS verification", 18),
    (
        r"except[^\n:]*:\s*(?:pass|\.\.\.)",
        "swallows exceptions",
        10,
    ),
    (r"#\s*(?:nosec|noqa)|--no-verify", "suppresses a scanner", 10),
    (r"\b(?:todo|fixme)\b", "leaves a TODO/FIXME", 5),
    (r"chmod\s+0?777", "makes files world-writable", 15),
    (r"\b(?:md5|sha1)\b", "uses a weak hash", 10),
    (
        r"random\.(?:random|randint)|math\.random",
        "uses non-crypto randomness",
        8,
    ),
    (
        r"(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]",
        "hardcodes a secret",
        18,
    ),
    (r"pickle\.loads?\s*\(", "keeps unsafe pickle loading", 15),
    (r"yaml\.load\s*\((?!.*Loader)", "keeps unsafe yaml.load", 12),
    (
        r"(?:disable|skip|ignore)\w*\s+(?:check|validation|verification)",
        "disables a check",
        12,
    ),
    (
        r"(?:execute|executemany)\s*\([^)]*\+",
        "concatenates input into a query",
        16,
    ),
    (
        r"(?:execute|executemany)\s*\([^)]*\.format\s*\(",
        "formats input into a query",
        16,
    ),
    (
        r"f['\"][^'\"]*(?:select|insert|update|delete)[^'\"]*\{",
        "uses an f-string query",
        16,
    ),
    (r"innerHTML\s*=", "writes raw HTML", 12),
    (r"dangerouslySetInnerHTML", "uses dangerouslySetInnerHTML", 12),
)

_TEMPLATE_LIBRARY: dict[str, tuple[tuple[str, str, str], ...]] = {
    "injection": (
        (
            "parameterized-query",
            "Replace string-built queries/commands with a bound parameter or "
            "an argv array.",
            "cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))\n"
            "# or: subprocess.run([cmd, user_arg], check=True)",
        ),
        (
            "input-allowlist",
            "Validate the untrusted value against a strict allowlist before "
            "it reaches the sink.",
            "if user_id not in allowed_ids:\n"
            "    raise ValueError('invalid id')\n"
            "cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
        ),
        (
            "defense-in-depth",
            "Keep the safe API and add a regression test plus a second "
            "control for encoded variants.",
            "def test_injection_regression():\n"
            "    payload = \"' OR '1'='1\"\n"
            "    assert payload not in call_the_sink(payload)",
        ),
    ),
    "xss": (
        (
            "context-encoding",
            "Encode output for the exact HTML/JS/URL context instead of "
            "writing raw markup.",
            "element.textContent = user_value\n"
            "# template engines: enable autoescape by default",
        ),
        (
            "vetted-sanitizer",
            "Use a maintained sanitizer with an explicit allowlist when "
            "markup is genuinely required.",
            "clean = bleach.clean(user_html, tags=allowed_tags)\n"
            "element.innerHTML = clean",
        ),
        (
            "defense-in-depth",
            "Add a CSP and a regression test for encoded and attribute " "contexts.",
            "def test_xss_regression():\n"
            "    payload = \"<script>alert('H4K')</script>\"\n"
            "    assert payload not in render(payload)",
        ),
    ),
    "path": (
        (
            "canonicalize-and-confine",
            "Resolve the path and confirm it stays under a fixed base " "directory.",
            "base = os.path.realpath(BASE_DIR)\n"
            "target = os.path.realpath(os.path.join(base, user_path))\n"
            "if not target.startswith(base + os.sep):\n"
            "    raise ValueError('path escape')",
        ),
        (
            "filename-allowlist",
            "Accept only known filenames or identifiers instead of a raw "
            "path fragment.",
            "if user_name not in allowed_files:\n"
            "    raise ValueError('unknown file')",
        ),
        (
            "defense-in-depth",
            "Combine canonicalization with a regression test for encoded "
            "traversal variants.",
            "def test_path_regression():\n"
            "    payload = '../../../../etc/hostname'\n"
            "    assert safe_join(payload) is None",
        ),
    ),
    "memory": (
        (
            "bounds-checked-copy",
            "Replace the unbounded copy with a length-checked API.",
            'snprintf(dst, sizeof(dst), "%s", src);\n'
            "// or: strlcpy(dst, src, sizeof(dst));",
        ),
        (
            "length-validation",
            "Reject inputs that cannot fit before touching the buffer.",
            "if (src_len >= sizeof(dst)) {\n" "    return -1;\n" "}",
        ),
        (
            "memory-safe-container",
            "Use a length-aware container or span instead of raw pointers.",
            "std::string dst(src, src_len);\n"
            "// or: std::span<const char> view(src, src_len);",
        ),
    ),
    "deserialization": (
        (
            "safe-loader",
            "Deserialize with a safe loader or an explicit class allowlist.",
            "data = yaml.safe_load(untrusted_text)\n"
            "# or: json.loads(untrusted_text)",
        ),
        (
            "signed-payload",
            "Verify a signature or MAC before deserializing.",
            "if not verify_hmac(payload, signature, key):\n"
            "    raise ValueError('unsigned payload')",
        ),
        (
            "defense-in-depth",
            "Add a regression test with a benign non-serialized marker.",
            "def test_deserialization_regression():\n"
            "    payload = 'H4K_TEST_MARKER'\n"
            "    assert load(payload) is None",
        ),
    ),
    "ssrf": (
        (
            "destination-allowlist",
            "Allow only known hosts/schemes before issuing the request.",
            "host = urlsplit(user_url).hostname\n"
            "if host not in allowed_hosts:\n"
            "    raise ValueError('destination not allowed')",
        ),
        (
            "private-address-check",
            "Resolve the destination and reject private, loopback and "
            "link-local addresses.",
            "ip = ipaddress.ip_address(socket.gethostbyname(host))\n"
            "if not ip.is_global:\n"
            "    raise ValueError('private destination')",
        ),
        (
            "defense-in-depth",
            "Re-check after redirects and add a regression test with a "
            "loopback marker.",
            "def test_ssrf_regression():\n"
            "    assert fetch('http://127.0.0.1:1/') is None",
        ),
    ),
    "auth": (
        (
            "server-side-authorization",
            "Require authentication and re-check authorization on the "
            "server for every request.",
            "@require_login\n"
            "def handler(request):\n"
            "    authorize(request.user, 'resource:read')",
        ),
        (
            "fail-closed",
            "Deny by default and return a safe error when the check is "
            "missing or inconclusive.",
            "if not user_has_permission(user, action):\n"
            "    raise PermissionError('denied')",
        ),
        (
            "defense-in-depth",
            "Add least privilege and a regression test for the "
            "unauthenticated path.",
            "def test_auth_regression():\n"
            "    assert client.get('/admin').status_code == 403",
        ),
    ),
    "info": (
        (
            "redact-response",
            "Return only the fields the caller needs and mask secrets.",
            "return {'id': item.id, 'name': item.name}\n"
            "# never return password/token/internal_path",
        ),
        (
            "authorize-sensitive-fields",
            "Gate sensitive fields behind an authorization check.",
            "if not can_view_secrets(user):\n" "    return public_view(item)",
        ),
        (
            "defense-in-depth",
            "Use generic errors and add a regression test for the " "redaction.",
            "def test_info_regression():\n"
            "    body = json.dumps(handler())\n"
            "    assert 'password' not in body",
        ),
    ),
    "generic": (
        (
            "validate-input",
            "Validate the untrusted value at the trust boundary and reject "
            "anything unexpected.",
            "if not is_valid(user_value):\n" "    raise ValueError('invalid input')",
        ),
        (
            "safe-api",
            "Replace the risky API with the safe equivalent for this "
            "language/framework.",
            "# use the parameterized / bounded / encoded API instead of the\n"
            "# string-building one",
        ),
        (
            "defense-in-depth",
            "Add a regression test with a safe marker and a negative " "variant.",
            "def test_regression():\n"
            "    payload = 'H4K_TEST_MARKER'\n"
            "    assert payload not in run(payload)",
        ),
    ),
}

_PAYLOADS: dict[str, tuple[str, ...]] = {
    "injection": ("' OR '1'='1", "; echo H4K_TEST_MARKER", "${7*7}"),
    "xss": ("<script>alert('H4K')</script>", '"><img src=x onerror=alert(1)>'),
    "path": ("../../../../etc/hostname", "..%2f..%2f..%2fetc%2fhostname"),
    "memory": ("A" * 64, "A" * 16 + "%s%s%s"),
    "deserialization": ("H4K_TEST_MARKER", "not-a-valid-serialized-object"),
    "ssrf": ("http://127.0.0.1:1/", "http://localhost:1/h4k"),
    "auth": ("", "invalid-token"),
    "info": ("H4K_TEST_MARKER", ""),
    "generic": ("H4K_TEST_MARKER", ""),
}

_EVIDENCE_KEYS: dict[str, tuple[str, ...]] = {
    "reachable": ("reachable", "attacker_reachable", "exposed"),
    "user_input_reaches_sink": (
        "user_input_reaches_sink",
        "untrusted_input",
        "input_reaches_sink",
    ),
    "sanitizer_present": ("sanitizer_present", "validated", "encoded"),
    "version_affected": ("version_affected", "affected_version", "in_range"),
    "runtime_confirmed": ("runtime_confirmed", "reproduced", "confirmed"),
    "compensating_control": ("compensating_control", "mitigated"),
    "public_exposure": ("public_exposure", "internet_facing"),
    "requires_auth": ("requires_auth", "authenticated"),
}

_TRUE_WORDS = {
    "true",
    "yes",
    "y",
    "1",
    "present",
    "confirmed",
    "affected",
    "reachable",
    "public",
    "required",
    "in_range",
}
_FALSE_WORDS = {
    "false",
    "no",
    "n",
    "0",
    "absent",
    "none",
    "unaffected",
    "not_affected",
    "unreachable",
    "internal",
}


def _family(cwe: str) -> str:
    number = cwe.upper().replace("CWE-", "").replace("CWE_", "").strip()
    return _CWE_FAMILY.get(number, "generic")


def _normalize_cwe(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    match = _CWE_RE.search(text)
    if match:
        return f"CWE-{int(match.group(1))}"
    return text.upper()


def _normalize_finding(raw: dict[str, Any] | None) -> dict[str, Any]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("finding must be an object")
    return {
        "title": str(
            raw.get("title") or raw.get("name") or raw.get("rule_id") or ""
        ).strip(),
        "cwe": _normalize_cwe(raw.get("cwe")),
        "description": str(raw.get("description") or raw.get("detail") or "").strip(),
        "language": str(raw.get("language") or "").strip().lower(),
        "severity": str(raw.get("severity") or "MEDIUM").strip().upper(),
    }


def _normalize_patch(raw: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"patches[{index}] must be an object")
    text = raw.get("diff") or raw.get("code") or raw.get("patch") or raw.get("content")
    if not isinstance(text, str) or not text.strip():
        raise ValueError(f"patches[{index}] must include diff/code/patch text")
    if len(text) > MAX_TEXT:
        raise ValueError(f"patches[{index}] is too large")
    tests = raw.get("test_code") or raw.get("tests")
    has_tests = tests if isinstance(tests, bool) else bool(str(tests or "").strip())
    return {
        "name": str(
            raw.get("name") or raw.get("id") or f"candidate-{index + 1}"
        ).strip(),
        "description": str(raw.get("description") or raw.get("summary") or "").strip(),
        "text": text,
        "has_tests": has_tests,
        "source": "supplied",
    }


def _template_patches(finding: dict[str, Any]) -> list[dict[str, Any]]:
    family = _family(str(finding.get("cwe") or ""))
    entries = _TEMPLATE_LIBRARY.get(family, _TEMPLATE_LIBRARY["generic"])
    cwe = str(finding.get("cwe") or "the reported weakness")
    title = str(finding.get("title") or "the finding")
    return [
        {
            "name": name,
            "description": f"{summary} ({cwe}: {title})",
            "text": code,
            "has_tests": False,
            "source": "template",
        }
        for name, summary, code in entries
    ]


def _score_patch(
    finding: dict[str, Any], patch: dict[str, Any], index: int
) -> dict[str, Any]:
    text = str(patch["text"])
    lower = text.lower()
    family = _family(str(finding.get("cwe") or ""))
    controls = _FAMILY_CONTROLS.get(family, ()) + _FAMILY_CONTROLS["generic"]
    score = 45
    signals: list[str] = []
    for pattern, label, weight in controls:
        if re.search(pattern, lower):
            score += weight
            signals.append(label)
    signals = list(dict.fromkeys(signals))

    anti: list[str] = []
    for pattern, label, weight in _ANTI_PATTERNS:
        if re.search(pattern, lower):
            score -= weight
            anti.append(label)
    anti = list(dict.fromkeys(anti))

    has_tests = bool(patch.get("has_tests")) or bool(
        re.search(r"\b(?:test_|pytest|unittest|jest|go test|assert)\b", lower)
    )
    if has_tests:
        score += 8
        signals.append("includes a regression test")

    size = len(text)
    if size <= 1200:
        score += 3
    elif size > 8000:
        score -= 6
        anti.append("large diff")
    if size > MAX_TEXT:
        anti.append("oversized patch")

    score = max(0, min(100, score))
    pros = signals or ["no CWE-specific control detected; review manually"]
    cons = anti or ["no obvious hardening gap detected in the text"]
    if not has_tests:
        cons.append("no regression test in the candidate")
    if score >= 75:
        confidence = "high"
    elif score >= 50:
        confidence = "medium"
    else:
        confidence = "low"
    return {
        "name": str(patch["name"]),
        "description": str(patch.get("description") or ""),
        "source": str(patch.get("source") or "supplied"),
        "score": score,
        "confidence": confidence,
        "signals": signals,
        "anti_patterns": anti,
        "tradeoffs": {"pros": pros, "cons": cons},
        "has_tests": has_tests,
        "size": size,
        "_index": index,
    }


def rank_patches(
    finding: dict[str, Any] | None, patches: list[Any] | None = None
) -> list[dict[str, Any]]:
    """Rank supplied candidates (or three templates) for the finding's CWE."""
    if finding is not None and not isinstance(finding, dict):
        raise ValueError("finding must be an object")
    normalized_finding = _normalize_finding(finding)
    if patches is None:
        patches = []
    if not isinstance(patches, list):
        raise ValueError("patches must be a list")
    if len(patches) > MAX_PATCHES:
        raise ValueError(f"at most {MAX_PATCHES} patches are supported")
    candidates = (
        [_normalize_patch(raw, index) for index, raw in enumerate(patches)]
        if patches
        else _template_patches(normalized_finding)
    )
    scored = [
        _score_patch(normalized_finding, candidate, index)
        for index, candidate in enumerate(candidates)
    ]
    scored.sort(key=lambda item: (-int(item["score"]), int(item["_index"])))
    for rank, item in enumerate(scored, start=1):
        item["rank"] = rank
        item["recommended"] = rank == 1
        item.pop("_index", None)
    return scored


def _slug(finding: dict[str, Any]) -> str:
    base = (
        str(finding.get("cwe") or "") or str(finding.get("title") or "") or "finding"
    ).lower()
    slug = _SLUG_RE.sub("_", base).strip("_")[:40]
    return slug or "finding"


def _steps(finding: dict[str, Any], payloads: tuple[str, ...]) -> list[str]:
    cwe = str(finding.get("cwe") or "the reported weakness")
    title = str(finding.get("title") or "the finding")
    return [
        f"Reproduce {cwe} ({title}) on the vulnerable build with the safe "
        f"marker payload {payloads[0]!r}.",
        "Record the observed unsafe behavior (marker reaches the sink, crash "
        "or unexpected result).",
        "Apply the candidate patch and re-run the same input.",
        "Assert the marker no longer reaches the sink and no crash occurs.",
        "Add the encoded/alternate variant as a negative regression case.",
    ]


def generate_tests(
    finding: dict[str, Any] | None,
    language: str = "",
    framework: str = "",
) -> dict[str, Any]:
    """Generate a deterministic regression-test skeleton for the finding."""
    normalized = _normalize_finding(finding)
    family = _family(str(normalized.get("cwe") or ""))
    payloads = _PAYLOADS.get(family, _PAYLOADS["generic"])
    slug = _slug(normalized)
    cwe = str(normalized.get("cwe") or "unclassified")
    title = str(normalized.get("title") or "the finding")
    steps = _steps(normalized, payloads)
    lang = (language or str(normalized.get("language") or "python")).strip().lower()

    if lang in {"py", "python"}:
        framework = framework or "pytest"
        filename = f"test_{slug}_regression.py"
        code = (
            f'"""Regression test skeleton for {cwe}: {title}.\n\n'
            "Replace call_the_vulnerable_function with the real entry point.\n"
            '"""\n\n\n'
            f"def test_{slug}_regression() -> None:\n"
            f'    """The safe marker must not reach the unsafe sink."""\n'
            f"    payload = {payloads[0]!r}\n"
            "    result = call_the_vulnerable_function(payload)\n"
            "    assert result is not None\n"
            f"    assert {payloads[0]!r} not in str(result)\n\n\n"
            f"def test_{slug}_rejects_encoded_variant() -> None:\n"
            f"    payload = {payloads[1]!r}\n"
            "    result = call_the_vulnerable_function(payload)\n"
            f"    assert {payloads[1]!r} not in str(result)\n"
        )
    elif lang in {"js", "javascript", "node", "ts", "typescript"}:
        framework = framework or "jest"
        filename = f"{slug}.regression.test.js"
        code = (
            f"// Regression test skeleton for {cwe}: {title}\n"
            f"test('{slug} rejects the unsafe marker', () => {{\n"
            f"  const payload = {payloads[0]!r};\n"
            "  const result = callTheVulnerableFunction(payload);\n"
            "  expect(String(result)).not.toContain(payload);\n"
            "});\n"
        )
    elif lang in {"go", "golang"}:
        framework = framework or "testing"
        go_name = "".join(part.capitalize() for part in slug.split("_")) or "Finding"
        filename = f"{slug}_regression_test.go"
        code = (
            f"// Regression test skeleton for {cwe}: {title}\n"
            f"func Test{go_name}(t *testing.T) {{\n"
            f"\tpayload := {payloads[0]!r}\n"
            "\tresult := callTheVulnerableFunction(payload)\n"
            "\tif strings.Contains(result, payload) {\n"
            '\t\tt.Fatalf("unsafe marker reached the sink: %q", result)\n'
            "\t}\n"
            "}\n"
        )
    else:
        framework = framework or "generic"
        filename = f"{slug}_regression.txt"
        code = (
            f"# Regression test skeleton for {cwe}: {title}\n"
            + "\n".join(f"- {step}" for step in steps)
            + "\n"
        )

    return {
        "language": lang,
        "framework": framework,
        "filename": filename,
        "test_name": f"test_{slug}_regression",
        "code": code,
        "payloads": list(payloads),
        "steps": steps,
        "assertions": [
            "the unsafe marker is rejected or encoded before the sink",
            "the vulnerable build crashes or misbehaves on the same input",
            "the fixed build returns safely for every listed variant",
        ],
        "negative_cases": list(payloads[1:]),
        "notes": (
            "Skeleton only: wire call_the_vulnerable_function to the real "
            "entry point and keep payloads non-destructive."
        ),
    }


def _tri(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in _TRUE_WORDS:
        return True
    if text in _FALSE_WORDS:
        return False
    return None


def _normalize_evidence(raw: dict[str, Any] | None) -> dict[str, bool | None]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("evidence must be an object")
    out: dict[str, bool | None] = {}
    for canonical, aliases in _EVIDENCE_KEYS.items():
        for key in (canonical, *aliases):
            if key in raw:
                out[canonical] = _tri(raw[key])
                break
    return out


def judge_false_positive(
    finding: dict[str, Any] | None, evidence: dict[str, Any] | None
) -> dict[str, Any]:
    """Conservative evidence-weighted verdict for the finding."""
    _normalize_finding(finding)
    ev = _normalize_evidence(evidence)
    score = 50
    reasons: list[str] = []

    def weigh(key: str, yes_weight: int, no_weight: int, yes: str, no: str) -> None:
        nonlocal score
        value = ev.get(key)
        if value is True:
            score += yes_weight
            reasons.append(yes)
        elif value is False:
            score += no_weight
            reasons.append(no)

    weigh(
        "runtime_confirmed",
        45,
        -5,
        "runtime reproduction confirms the issue",
        "not reproduced at runtime (does not by itself prove a false positive)",
    )
    weigh(
        "user_input_reaches_sink",
        25,
        -30,
        "untrusted input reaches the sink",
        "untrusted input does not reach the sink on the reviewed path",
    )
    weigh(
        "reachable",
        15,
        -20,
        "the vulnerable code is reachable from an entry point",
        "the vulnerable code is not reachable from an exposed entry point",
    )
    weigh(
        "sanitizer_present",
        -25,
        10,
        "a sanitizer is present",
        "no sanitizer is present",
    )
    weigh(
        "version_affected",
        15,
        -35,
        "the deployed version is in the affected range",
        "the deployed version is outside the affected range",
    )
    weigh(
        "compensating_control",
        -20,
        5,
        "a compensating control is present",
        "no compensating control is present",
    )
    weigh(
        "public_exposure",
        10,
        -5,
        "the target is publicly exposed",
        "the target is not publicly exposed",
    )
    weigh(
        "requires_auth",
        -5,
        5,
        "authentication is required (reduces exposure, not a false positive)",
        "no authentication is required",
    )

    clearing = sum(
        1
        for key in (
            "user_input_reaches_sink",
            "reachable",
            "sanitizer_present",
            "version_affected",
            "compensating_control",
        )
        if (
            (key in {"user_input_reaches_sink", "reachable"} and ev.get(key) is False)
            or (
                key in {"sanitizer_present", "compensating_control"}
                and ev.get(key) is True
            )
            or (key == "version_affected" and ev.get(key) is False)
        )
    )
    contrary = (
        ev.get("runtime_confirmed") is True
        or ev.get("user_input_reaches_sink") is True
        or ev.get("reachable") is True
    )
    if ev.get("runtime_confirmed") is True:
        verdict = "confirmed"
    elif score >= 65 and not clearing:
        verdict = "likely_true_positive"
    elif score <= 25 and clearing >= 2 and not contrary:
        verdict = "false_positive"
    elif score <= 40 and clearing >= 1 and not contrary:
        verdict = "likely_false_positive"
    else:
        verdict = "needs_review"

    why_not: list[str] = []
    if verdict in {"false_positive", "likely_false_positive"}:
        if ev.get("reachable") is False:
            why_not.append(
                "the vulnerable code is not reachable from an exposed entry point"
            )
        if ev.get("user_input_reaches_sink") is False:
            why_not.append(
                "untrusted input does not reach the sink on the reviewed path"
            )
        if ev.get("sanitizer_present") is True:
            why_not.append("input is validated or encoded before the sink")
        if ev.get("version_affected") is False:
            why_not.append("the deployed version is outside the affected range")
        if ev.get("compensating_control") is True:
            why_not.append("a compensating control blocks the attack path")

    if not reasons:
        reasons.append(
            "no evidence supplied; the finding cannot be cleared or confirmed"
        )

    missing = [key for key in _EVIDENCE_KEYS if ev.get(key) is None]
    confidence = min(95, 50 + abs(score - 50))
    if verdict == "confirmed":
        confidence = max(confidence, 95)
    elif verdict == "needs_review":
        confidence = min(confidence, 55)
    return {
        "verdict": verdict,
        "score": max(0, min(100, score)),
        "confidence": confidence,
        "reasons": reasons,
        "why_not_exploitable": why_not,
        "missing_evidence": missing,
        "evidence": {key: ev.get(key) for key in _EVIDENCE_KEYS},
        "notes": (
            "Conservative by design: false_positive/likely_false_positive "
            "require positive clearing evidence and no runtime confirmation."
        ),
    }


def analyze(
    finding: dict[str, Any] | None = None,
    patches: list[Any] | None = None,
    test_language: str = "",
    test_framework: str = "",
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Combine whichever review sections the request asked for."""
    if finding is not None and not isinstance(finding, dict):
        raise ValueError("finding must be an object")
    if patches is None:
        patches = []
    if not isinstance(patches, list):
        raise ValueError("patches must be a list")
    if evidence is not None and not isinstance(evidence, dict):
        raise ValueError("evidence must be an object")
    if finding is None and not patches and evidence is None:
        raise ValueError("finding, patches or evidence required")

    normalized = _normalize_finding(finding)
    ranked = rank_patches(normalized, patches) if (normalized or patches) else []
    tests = (
        generate_tests(normalized, test_language, test_framework)
        if (normalized or patches)
        else None
    )
    judgement = (
        judge_false_positive(normalized, evidence) if evidence is not None else None
    )
    recommended = ranked[0] if ranked else None
    return {
        "finding": normalized,
        "patches": ranked,
        "recommended": recommended,
        "tests": tests,
        "false_positive": judgement,
        "summary": {
            "patch_count": len(ranked),
            "recommended_patch": str((recommended or {}).get("name") or ""),
            "recommended_score": int((recommended or {}).get("score") or 0),
            "verdict": str((judgement or {}).get("verdict") or ""),
            "test_language": str((tests or {}).get("language") or ""),
        },
        "limitations": LIMITATIONS,
        "sandbox": False,
    }


def to_ledger(host: str, result: dict[str, Any]) -> list[dict[str, Any]]:
    """Ledger only a confirmed/likely true positive, never a cleared finding."""
    judgement = result.get("false_positive") or {}
    verdict = str(judgement.get("verdict") or "")
    if verdict not in {"confirmed", "likely_true_positive"}:
        return []
    finding = result.get("finding") or {}
    cwe = str(finding.get("cwe") or "").strip()
    title = str(finding.get("title") or cwe or "reviewed finding").strip()
    severity = str(finding.get("severity") or "MEDIUM").strip().upper()
    recommended = str((result.get("recommended") or {}).get("name") or "")
    reasons = "; ".join(str(item) for item in judgement.get("reasons") or [])
    detail = (
        f"verdict={verdict} confidence={judgement.get('confidence')} "
        f"recommended_patch={recommended} reasons={reasons}"
    )
    return [
        {
            "host": host,
            "name": f"review: {title}"[:220],
            "severity": severity,
            "module": "patch-review",
            "reference": cwe,
            "cwe": cwe,
            "detail": detail[:400],
        }
    ]


def sandbox_result() -> dict[str, Any]:
    """Deterministic canned review result for sandbox mode and CI."""
    result = analyze(
        finding={
            "title": "SQL injection in login lookup",
            "cwe": "CWE-89",
            "severity": "HIGH",
            "language": "python",
            "description": "user input concatenated into a SQL query",
        },
        patches=[
            {
                "name": "parameterized-query",
                "diff": "cursor.execute('SELECT * FROM users WHERE name = %s', (name,))",
            },
            {
                "name": "string-concat",
                "diff": "cursor.execute('SELECT * FROM users WHERE name = ' + name)  # nosec",
            },
            {
                "name": "allowlist-then-parameterize",
                "diff": (
                    "if name not in allowed_users:\n"
                    "    raise ValueError('unknown user')\n"
                    "cursor.execute('SELECT * FROM users WHERE name = %s', (name,))"
                ),
            },
        ],
        evidence={
            "reachable": True,
            "user_input_reaches_sink": True,
            "version_affected": True,
            "runtime_confirmed": False,
            "sanitizer_present": False,
        },
    )
    result["sandbox"] = True
    return result
