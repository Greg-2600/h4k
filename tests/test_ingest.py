# Tests for the source-ingest service (archive extraction + git clone planning).
import io
import tarfile
import zipfile

import pytest
from services.ingest import (
    IngestError,
    clone_git,
    extract_archive,
    find_source_root,
    is_archive,
    make_workdir,
    normalize_source_name,
)


def test_is_archive():
    assert is_archive("x.zip")
    assert is_archive("x.tar")
    assert is_archive("x.tar.gz")
    assert is_archive("x.tgz")
    assert not is_archive("x.py")


def test_normalize_source_name():
    assert normalize_source_name("proj-1.0.zip") == "proj-1.0"
    assert normalize_source_name("proj.tar.gz") == "proj"
    assert normalize_source_name("proj.tgz") == "proj"


def _make_zip_payload() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("src/app.py", "print('hi')\n")
        zf.writestr("src/util.py", "def f(): return 1\n")
    return buf.getvalue()


def _make_targz_payload() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"x=eval(y)\n"
        info = tarfile.TarInfo("src/app.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_extract_zip(tmp_path):
    n = extract_archive(_make_zip_payload(), "proj.zip", tmp_path)
    assert n == 2
    assert (tmp_path / "src/app.py").exists()


def test_extract_tar_gz(tmp_path):
    n = extract_archive(_make_targz_payload(), "proj.tar.gz", tmp_path)
    assert n == 1
    assert (tmp_path / "src/app.py").exists()


def test_zip_slip_blocked(tmp_path):
    evil = io.BytesIO()
    with zipfile.ZipFile(evil, "w") as zf:
        zf.writestr("../../evil.txt", "boom")
    with pytest.raises(IngestError):
        extract_archive(evil.getvalue(), "e.zip", tmp_path)


def test_bad_archive(tmp_path):
    with pytest.raises(IngestError):
        extract_archive(b"not a real archive", "bad.zip", tmp_path)


def test_make_workdir_and_root(tmp_path):
    wd = make_workdir()
    assert wd.is_dir()


def test_find_source_root_nested(tmp_path):
    inner = tmp_path / "proj"
    inner.mkdir()
    (inner / "app.py").write_text("a")
    assert find_source_root(tmp_path) == inner


def test_clone_git_bad_url(tmp_path):
    with pytest.raises(IngestError):
        clone_git("https://this-repo-will-not-exist.invalid/x.git", tmp_path)
