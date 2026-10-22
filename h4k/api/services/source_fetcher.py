# Source Code Fetcher - Clones repositories and fetches source code for analysis.
# Supports Git, HTTP, and various source code hosting platforms.
import logging
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests

logger = logging.getLogger("h4k.source_fetcher")

# Known source code hosting patterns
REPO_PATTERNS = {
    "github": [
        r"github\.com/([^/]+)/([^/]+)",
        r"github\.com[:/]([^/]+)/([^/]+)",
    ],
    "gitlab": [
        r"gitlab\.com/([^/]+)/([^/]+)",
        r"gitlab\.com[:/]([^/]+)/([^/]+)",
    ],
    "bitbucket": [
        r"bitbucket\.org/([^/]+)/([^/]+)",
    ],
    "gitea": [
        r"github\.com/([^/]+)/([^/]+)",  # Same pattern as GitHub for Gitea
    ],
    "codeberg": [
        r"codeberg\.org/([^/]+)/([^/]+)",
    ],
    "sourcehut": [
        r"git\.sr\.ht/([^/]+)/([^/]+)",
    ],
}

VCS_COMMANDS = {
    "git": ["git", "clone", "--depth", "1", "--recurse-submodules"],
    "hg": ["hg", "clone"],
    "svn": ["svn", "checkout"],
}

ARCHIVE_EXTENSIONS = {".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar"}

# Language detection by file extension
LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".scala": "scala",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".pl": "perl",
    ".pm": "perl",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".ps1": "powershell",
    ".lua": "lua",
    ".r": "r",
    ".rkt": "racket",
    ".clj": "clojure",
    ".hs": "haskell",
    ".ml": "ocaml",
    ".fs": "fsharp",
    ".swift": "swift",
    ".m": "objective-c",
    ".mm": "objective-c++",
    ".vb": "vbnet",
    ".sql": "sql",
    ".html": "html",
    ".htm": "html",
    ".css": "css",
    ".scss": "scss",
    ".sass": "sass",
    ".less": "less",
    ".vue": "vue",
    ".svelte": "svelte",
    ".dart": "dart",
    ".zig": "zig",
    ".nim": "nim",
    ".cr": "crystal",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hrl": "erlang",
}


class SourceFetcher:
    """Fetches source code from various sources."""

    def __init__(
        self,
        work_dir: Path | str | None = None,
        max_size: int = 100 * 1024 * 1024,  # 100MB
        timeout: int = 300,
    ):
        self.work_dir = (
            Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="h4k_src_"))
        )
        self.max_size = max_size
        self.timeout = timeout
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def fetch(self, url: str, branch: str | None = None) -> dict:
        """Fetch source code from a URL."""
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if scheme in ("git", "git+ssh", "git+https", "git+http"):
            return self._clone_git(url, branch)
        elif scheme in ("http", "https"):
            # Check if it's a direct file or archive
            if any(url.endswith(ext) for ext in ARCHIVE_EXTENSIONS):
                return self._download_archive(url)
            # Try to detect if it's a repo URL
            return self._fetch_from_web(url)
        else:
            raise ValueError(f"Unsupported scheme: {scheme}")

    def _clone_git(self, url: str, branch: str | None = None) -> dict:
        """Clone a Git repository."""
        # Clean URL for git clone
        clone_url = url
        for prefix in ("git+ssh://", "git+https://", "git+http://", "git://"):
            if clone_url.startswith(prefix):
                clone_url = clone_url[len(prefix) :]
                break

        repo_name = self._get_repo_name(url)
        target_dir = self.work_dir / repo_name

        # Remove existing directory
        if target_dir.exists():
            shutil.rmtree(target_dir)

        cmd = ["git", "clone", "--depth", "1"]
        if branch:
            cmd += ["-b", branch]
        cmd += [clone_url, str(target_dir)]

        try:
            subprocess.run(  # nosec B603 B607
                cmd, capture_output=True, text=True, timeout=self.timeout, check=True
            )
        except subprocess.CalledProcessError as e:
            return {"success": False, "error": e.stderr}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Clone timed out"}

        # Get repository info
        info = self._get_repo_info(target_dir)
        return {
            "success": True,
            "path": str(target_dir),
            "url": url,
            "branch": branch,
            "info": info,
        }

    def _download_archive(self, url: str) -> dict:
        """Download and extract an archive."""
        urlparse(url)
        filename = os.path.basename(urlparse(url).path) or "archive"
        temp_path = self.work_dir / filename

        try:
            # Download
            response = requests.get(url, stream=True, timeout=self.timeout)
            response.raise_for_status()

            total_size = int(response.headers.get("content-length", 0))
            if total_size > self.max_size:
                return {
                    "success": False,
                    "error": f"Archive too large: {total_size} bytes",
                }

            with open(temp_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            # Extract
            extract_dir = self.work_dir / Path(filename).stem
            if extract_dir.exists():
                shutil.rmtree(extract_dir)

            shutil.unpack_archive(temp_path, extract_dir)
            temp_path.unlink()

            info = self._get_repo_info(extract_dir)
            return {
                "success": True,
                "path": str(extract_dir),
                "url": url,
                "info": info,
            }
        except Exception as e:
            if temp_path.exists():
                temp_path.unlink()
            return {"success": False, "error": str(e)}

    def _fetch_from_web(self, url: str) -> dict:
        """Fetch source from a web URL (GitHub, GitLab, etc.)."""
        # Try to detect the platform and convert to git URL
        git_url = self._convert_to_git_url(url)
        if git_url:
            return self._clone_git(git_url)

        # Try to download as archive
        if any(url.endswith(ext) for ext in ARCHIVE_EXTENSIONS):
            return self._download_archive(url)

        return {"success": False, "error": f"Unsupported URL: {url}"}

    def _convert_to_git_url(self, url: str) -> str | None:
        """Convert web URL to git clone URL."""
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        path = parsed.path.rstrip("/")

        # GitHub
        if "github.com" in host:
            match = re.match(r"/([^/]+)/([^/]+)", path)
            if match:
                owner, repo = match.groups()
                repo = repo.replace(".git", "")
                return f"https://github.com/{owner}/{repo}.git"

        # GitLab
        if "gitlab.com" in host:
            match = re.match(r"/([^/]+)/([^/]+)", path)
            if match:
                owner, repo = match.groups()
                repo = repo.replace(".git", "")
                return f"https://gitlab.com/{owner}/{repo}.git"

        # Bitbucket
        if "bitbucket.org" in host:
            match = re.match(r"/([^/]+)/([^/]+)", path)
            if match:
                owner, repo = match.groups()
                repo = repo.replace(".git", "")
                return f"https://bitbucket.org/{owner}/{repo}.git"

        # Codeberg
        if "codeberg.org" in host:
            match = re.match(r"/([^/]+)/([^/]+)", path)
            if match:
                owner, repo = match.groups()
                repo = repo.replace(".git", "")
                return f"https://codeberg.org/{owner}/{repo}.git"

        # SourceHut
        if "git.sr.ht" in host:
            match = re.match(r"/([^/]+)/([^/]+)", path)
            if match:
                owner, repo = match.groups()
                repo = repo.replace(".git", "")
                return f"https://git.sr.ht/{owner}/{repo}"

        return None

    def _get_repo_name(self, url: str) -> str:
        """Extract repository name from URL."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/").removesuffix(".git")
        parts = path.strip("/").split("/")
        return parts[-1] if parts else "repo"

    def _get_repo_info(self, repo_path: Path) -> dict:
        """Get repository metadata."""
        info = {
            "path": str(repo_path),
            "languages": {},
            "files": 0,
            "size_bytes": 0,
        }

        try:
            # Git info
            git_dir = repo_path / ".git"
            if git_dir.exists():
                # Get remote URL
                try:
                    result = subprocess.run(  # nosec B603 B607
                        [
                            "git",
                            "-C",
                            str(repo_path),
                            "config",
                            "--get",
                            "remote.origin.url",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        info["remote_url"] = result.stdout.strip()
                except Exception:  # nosec B110
                    pass

                # Get commit hash
                try:
                    result = subprocess.run(  # nosec B603 B607
                        ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if result.returncode == 0:
                        info["commit"] = result.stdout.strip()[:12]
                except Exception:  # nosec B110
                    pass

        # Count files and detect languages
        except Exception:  # nosec B110
            pass
        lang_counts: dict[str, int] = {}
        total_files = 0
        total_size = 0

        for file_path in Path(str(info["path"])).rglob("*"):
            if not file_path.is_file():
                continue
            try:
                size = file_path.stat().st_size
                total_size += size
                total_files += 1

                ext = file_path.suffix.lower()
                if ext in LANGUAGE_EXTENSIONS:
                    lang = LANGUAGE_EXTENSIONS[ext]
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1
            except Exception:  # nosec B112 - expected continue on error
                continue

        info["languages"] = lang_counts
        info["files"] = total_files
        info["size_bytes"] = total_size

        return info

    def cleanup(self) -> None:
        """Clean up work directory."""
        if self.work_dir.exists():
            shutil.rmtree(self.work_dir, ignore_errors=True)


def detect_vcs(url: str) -> str | None:
    """Detect version control system from URL."""
    url.lower()
    if url.endswith(".git") or "github.com" in url or "gitlab.com" in url:
        return "git"
    if "hg" in url or "mercurial" in url:
        return "hg"
    if "svn" in url or "subversion" in url:
        return "svn"
    return None


def is_source_url(url: str) -> bool:
    """Check if URL is likely a source code repository."""
    parsed = urlparse(url)
    host = parsed.netloc.lower()
    urlparse(url).path.lower()

    source_hosts = [
        "github.com",
        "github.io",
        "gitlab.com",
        "gitlab.io",
        "bitbucket.org",
        "codeberg.org",
        "sourcehut.org",
        "git.sr.ht",
        "github.io",
        "gitlab.io",
    ]

    for host in source_hosts:
        if host in url.lower():
            return True

    # Check for .git suffix
    if url.endswith(".git"):
        return True

    # Check for common patterns
    return bool(
        re.search(r"/[^/]+/[^/]+/?$", urlparse(url).path)
        and any(
            host in url
            for host in ["github", "gitlab", "bitbucket", "codeberg", "sourcehut"]
        )
    )


def fetch_source(url: str, work_dir: Path | None = None, **kwargs: Any) -> dict:
    """Convenience function to fetch source code."""
    fetcher = SourceFetcher(work_dir=kwargs.get("work_dir"))
    try:
        return fetcher.fetch(url, branch=kwargs.get("branch"))
    finally:
        if kwargs.get("cleanup", True):
            fetcher.cleanup()
