# Source-ingest service. Accepts an uploaded archive (zip / tar / tar.gz) or a
# git(SLab/generic) URL, verifies/extracts/clones it into a temp workspace, and
# returns the path for downstream analysis. Lab-only: the operator supplies code
# they're entitled to analyze.
import io
import logging
import shutil
import subprocess  # nosec B404 - runs git clone / extraction helpers
import tarfile
import tempfile
import zipfile
from pathlib import Path

logger = logging.getLogger("h4k.ingest")

# Keep extraction bounded to a sane demo size.
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024  # 200 MB
MAX_FILES = 20000

ALLOWED_EXT = {".zip", ".tar", ".tar.gz", ".tgz"}


class IngestError(Exception):
    pass


def normalize_source_name(name: str) -> str:
    base = Path(name).name
    for ext in (".tar.gz", ".tar", ".tgz", ".zip"):
        if base.endswith(ext):
            return base[: -len(ext)]
    return base or "source"


def is_archive(filename: str) -> bool:
    return (
        Path(filename).suffix in (".zip", ".gz", ".tgz")
        or filename.endswith(".tar")
        or filename.endswith(".tar.gz")
    )


def make_workdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="h4k-src-"))


def extract_archive(data: bytes, filename: str, dest: Path) -> int:
    """Extract archive bytes into dest/. Returns file count. Raises IngestError."""
    if len(data) > MAX_ARCHIVE_BYTES:
        raise IngestError("archive too large")
    if filename.endswith(".zip") or filename.lower().endswith(".zip"):
        return _extract_zip(data, dest)
    return _extract_tar(data, dest)


def _extract_zip(data: bytes, dest: Path) -> int:
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise IngestError("invalid zip") from exc
    count = 0
    with zf:
        for zi in zf.infolist():
            target = _safe_join(dest, zi.filename)
            if zi.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(zi) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            count += 1
            if count > MAX_FILES:
                raise IngestError("too many files")
    return count


def _extract_tar(data: bytes, dest: Path) -> int:
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            count = _extract_members(tf, dest)
    except tarfile.TarError as exc:
        raise IngestError("invalid tar") from exc
    return count


def _extract_members(tf: tarfile.TarFile, dest: Path) -> int:
    count = 0
    for ti in tf.getmembers():
        if ti.isdir():
            continue
        target = _safe_join(dest, ti.name)
        target.parent.mkdir(parents=True, exist_ok=True)
        src = tf.extractfile(ti)
        if src is None:
            continue
        with src, open(target, "wb") as out:
            shutil.copyfileobj(src, out)
        count += 1
        if count > MAX_FILES:
            raise IngestError("too many files")
    return count


def clone_git(url: str, dest: Path) -> int:
    """Clone a git repo (GitLab or any git URL). Returns filesystem size or 0."""
    try:
        proc = subprocess.run(  # nosec B603 B607 - argv, no shell; git via PATH
            ["git", "clone", "--depth", "1", "-q", url, str(dest)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError:
        raise IngestError("git not available") from None
    except subprocess.TimeoutExpired as exc:
        raise IngestError("git clone timed out") from exc
    if proc.returncode != 0:
        raise IngestError(f"git clone failed: {proc.stderr.strip()[:200]}")
    return 0


def find_source_root(dest: Path) -> Path:
    """If a single top-level dir was extracted (common for archives), use it."""
    try:
        children = [
            p for p in dest.iterdir() if p.is_dir() and not p.name.startswith(".")
        ]
        if len(children) == 1:
            return children[0]
    except OSError:
        pass
    return dest


def _safe_join(root: Path, name: str) -> Path:
    """Prevent path traversal in archive member names (zip-slip)."""
    target = (root / name).resolve()
    root_res = root.resolve()
    if not target.is_relative_to(root_res):
        raise IngestError("archive member escapes root (zip-slip)")
    return target
