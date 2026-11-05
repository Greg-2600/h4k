"""Reachability filter — import-graph prunes dead code (Backlog #64).

Offline dead-code triage for pasted sources: builds a module-level
import graph (Python via `ast`, JS/TS via import/require regexes, PHP
via use/include regexes), resolves each import against the files in
the bundle, and reports what no entry point can reach. Entry points
are explicit when given, otherwise files with a `__main__` guard or
`main`/`app`/`index`/`cli` names — stated in the output either way,
since a wrong root set is the classic way this analysis lies.

Findings are advisory (dead code is a maintenance smell, not a vuln,
so nothing ledgers): unreachable files plus unresolvable imports.
Sandbox returns a canned graph without parsing anything.
"""

from __future__ import annotations

import ast
import logging
import re
from typing import Any

logger = logging.getLogger("h4k.reachability")

_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[^'"]*?\s+from\s+)?['"]([^'"]+)['"]|"""
    r"""require\s*\(\s*['"]([^'"]+)['"]\s*\)|"""
    r"""import\s*\(\s*['"]([^'"]+)['"]\s*\))"""
)
_PHP_USE_RE = re.compile(r"^\s*use\s+([\w\\]+)", re.MULTILINE)
_PHP_INCLUDE_RE = re.compile(
    r"""(?:include|require)(?:_once)?\s*\(?\s*['"]([^'"]+)['"]"""
)

_ENTRY_NAME_RE = re.compile(
    r"(?:^|[/_])(?:main|app|index|cli|__main__)(?:\.|$)", re.IGNORECASE
)


def _lang_of(path: str) -> str | None:
    lowered = (path or "").lower()
    if lowered.endswith(".py"):
        return "python"
    if lowered.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        return "javascript"
    if lowered.endswith((".php", ".phtml")):
        return "php"
    return None


def _py_imports(content: str) -> list[str]:
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return []
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                out.append(node.module.split(".")[0])
            elif node.level:
                out.append(".")
    return out


def _js_imports(content: str) -> list[str]:
    out: list[str] = []
    for match in _JS_IMPORT_RE.finditer(content):
        spec = next((g for g in match.groups() if g), "")
        if spec.startswith("."):
            out.append(spec)
        elif "/" not in spec or spec.startswith("@"):
            out.append(spec.split("/")[0].lstrip("@"))
        else:
            out.append(spec)
    return out


def _php_imports(content: str) -> list[str]:
    out: list[str] = []
    for match in _PHP_USE_RE.finditer(content):
        out.append(match.group(1).split("\\")[0])
    for match in _PHP_INCLUDE_RE.finditer(content):
        out.append(match.group(1))
    return out


def _module_key(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    return re.sub(
        r"\.(py|js|jsx|ts|tsx|mjs|cjs|php|phtml)$", "", base, flags=re.IGNORECASE
    )


def _resolves(spec: str, by_module: dict[str, str], path: str) -> str | None:
    if not spec:
        return None
    if spec == ".":
        return path  # explicit relative import of the same package dir
    if spec.startswith("."):
        # Same-directory relative hops (./util, ../util) resolve by basename;
        # deeper package layouts are out of scope and stay unresolved.
        cand = spec.split("/")[-1]
        cand = re.sub(r"\.(js|jsx|ts|tsx|mjs|cjs|py|php|phtml)$", "", cand)
        if cand and cand in by_module:
            return by_module[cand]
        return None
    stem = spec.split("/")[0].removesuffix(".js").removesuffix(".ts")
    if stem in by_module:
        return by_module[stem]
    if spec in by_module:
        return by_module[spec]
    return None


def analyze(
    files: list[dict[str, str]],
    entries: list[str] | None = None,
) -> dict[str, Any]:
    """Build the import graph and split files into reached/unreached."""
    if not files:
        raise ValueError("bundle or files required (paste sources)")
    paths = [str(f.get("path") or "file").strip() or "file" for f in files]
    contents = [str(f.get("content") or "") for f in files]
    langs = [_lang_of(p) for p in paths]
    by_module: dict[str, str] = {}
    for path in paths:
        by_module.setdefault(_module_key(path), path)
        by_module.setdefault(path, path)
        by_module.setdefault("./" + path, path)

    edges: dict[str, list[str]] = {p: [] for p in paths}
    unresolved: list[dict[str, str]] = []
    for path, content, lang in zip(paths, contents, langs, strict=True):
        specs: list[str] = []
        if lang == "python":
            specs = _py_imports(content)
        elif lang == "javascript":
            specs = _js_imports(content)
        elif lang == "php":
            specs = _php_imports(content)
        else:
            continue
        for spec in specs:
            target = _resolves(spec, by_module, path)
            if target is not None and target != path and target not in edges[path]:
                edges[path].append(target)
            elif target is None:
                unresolved.append({"file": path, "import": spec})

    if entries:
        roots = [e for e in entries if e in edges]
        unknown = [e for e in entries if e not in edges]
    else:
        roots = [
            p
            for p, c in zip(paths, contents, strict=True)
            if "__main__" in c or _ENTRY_NAME_RE.search(p)
        ]
        unknown = []
        if not roots:
            roots = list(paths)
    reached: set[str] = set()
    stack = list(roots)
    while stack:
        node = stack.pop()
        if node in reached:
            continue
        reached.add(node)
        stack.extend(n for n in edges.get(node, []) if n not in reached)
    unreachable = [p for p in paths if p not in reached]
    return {
        "files": len(paths),
        "entries": roots,
        "entry_guessed": not bool(entries),
        "unknown_entries": unknown,
        "edges": edges,
        "reachable": sorted(reached),
        "reachable_count": len(reached),
        "unreachable": sorted(unreachable),
        "unreachable_count": len(unreachable),
        "unresolved": unresolved,
        "pruned_ratio": round(len(unreachable) / max(len(paths), 1), 2),
    }


def sandbox_result() -> dict[str, Any]:
    """Canned graph (nothing parsed)."""
    return {
        "files": 3,
        "entries": ["app.py"],
        "entry_guessed": True,
        "unknown_entries": [],
        "edges": {"app.py": ["util.py"], "util.py": [], "legacy.py": []},
        "reachable": ["app.py", "util.py"],
        "reachable_count": 2,
        "unreachable": ["legacy.py"],
        "unreachable_count": 1,
        "unresolved": [{"file": "app.py", "import": "os"}],
        "pruned_ratio": 0.33,
        "sandbox": True,
    }
