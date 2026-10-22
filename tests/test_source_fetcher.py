# Tests for source_fetcher.py
from unittest.mock import MagicMock, patch

import pytest

from h4k.api.services.source_fetcher import (
    SourceFetcher,
    detect_vcs,
    fetch_source,
    is_source_url,
)


class TestDetectVcs:
    def test_github_git_suffix(self):
        assert detect_vcs("https://github.com/user/repo.git") == "git"

    def test_github_no_suffix(self):
        assert detect_vcs("https://github.com/user/repo") == "git"

    def test_gitlab(self):
        assert detect_vcs("https://gitlab.com/user/repo") == "git"

    def test_mercurial(self):
        assert detect_vcs("https://hg.example.com/repo") == "hg"

    def test_subversion(self):
        assert detect_vcs("https://svn.example.com/repo") == "svn"

    def test_unknown(self):
        assert detect_vcs("https://example.com/file.txt") is None


class TestIsSourceUrl:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://github.com/user/repo", True),
            ("https://github.com/user/repo.git", True),
            ("https://gitlab.com/user/repo", True),
            ("https://bitbucket.org/user/repo", True),
            ("https://codeberg.org/user/repo", True),
            ("https://git.sr.ht/~user/repo", True),
            ("https://github.io/user/repo", True),
            ("https://gitlab.io/user/repo", True),
            ("https://example.com/download.tar.gz", False),
            ("https://python.org", False),
            ("https://example.com/file.txt", False),
        ],
    )
    def test_is_source_url(self, url, expected):
        assert is_source_url(url) == expected


class TestSourceFetcherInit:
    def test_creates_work_dir(self, tmp_path):
        SourceFetcher(work_dir=tmp_path / "work")
        assert (tmp_path / "work").exists()

    def test_custom_max_size(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path / "w", max_size=1024)
        assert fetcher.max_size == 1024

    def test_custom_timeout(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path / "w", timeout=60)
        assert fetcher.timeout == 60


class TestSourceFetcherGetRepoName:
    def test_simple(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        assert fetcher._get_repo_name("https://github.com/owner/repo.git") == "repo"
        assert fetcher._get_repo_name("https://github.com/owner/repo") == "repo"

    def test_strips_git(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        assert fetcher._get_repo_name("https://gitlab.com/org/project.git") == "project"


class TestSourceFetcherConvertToGitUrl:
    def test_github(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        url = fetcher._convert_to_git_url("https://github.com/owner/repo")
        assert url == "https://github.com/owner/repo.git"

    def test_github_with_branch_returns_url(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        url = fetcher._convert_to_git_url("https://github.com/owner/repo/tree/main")
        assert url == "https://github.com/owner/repo.git"

    def test_gitlab(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        url = fetcher._convert_to_git_url("https://gitlab.com/owner/repo")
        assert url == "https://gitlab.com/owner/repo.git"

    def test_bitbucket(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        url = fetcher._convert_to_git_url("https://bitbucket.org/owner/repo")
        assert url == "https://bitbucket.org/owner/repo.git"

    def test_codeberg(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        url = fetcher._convert_to_git_url("https://codeberg.org/owner/repo")
        assert url == "https://codeberg.org/owner/repo.git"

    def test_sourcehut(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        url = fetcher._convert_to_git_url("https://git.sr.ht/~owner/repo")
        assert url == "https://git.sr.ht/~owner/repo"

    def test_strips_dot_git(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        url = fetcher._convert_to_git_url("https://github.com/owner/repo.git")
        assert url == "https://github.com/owner/repo.git"

    def test_unknown_returns_none(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        assert fetcher._convert_to_git_url("https://example.com/owner/repo") is None


class TestSourceFetcherFetch:
    def test_unsupported_scheme(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path)
        with pytest.raises(ValueError, match="Unsupported scheme"):
            fetcher.fetch("ftp://example.com/repo")

    @patch("h4k.api.services.source_fetcher.SourceFetcher._clone_git")
    def test_git_scheme(self, mock_clone, tmp_path):
        mock_clone.return_value = {"success": True, "path": "/tmp/repo"}
        fetcher = SourceFetcher(work_dir=tmp_path)
        result = fetcher.fetch("git://github.com/owner/repo")
        assert result["success"] is True
        mock_clone.assert_called_once()

    @patch("h4k.api.services.source_fetcher.SourceFetcher._download_archive")
    def test_https_archive(self, mock_dl, tmp_path):
        mock_dl.return_value = {"success": True, "path": "/tmp/archive"}
        fetcher = SourceFetcher(work_dir=tmp_path)
        fetcher.fetch("https://example.com/repo.tar.gz")
        mock_dl.assert_called_once()


class TestSourceFetcherCloneGit:
    @patch("subprocess.run")
    def test_clone_success(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(SourceFetcher, "_get_repo_info", return_value={}):
            fetcher = SourceFetcher(work_dir=tmp_path)
            result = fetcher._clone_git("https://github.com/owner/repo.git")
        assert result["success"] is True
        assert "path" in result
        assert result["url"] == "https://github.com/owner/repo.git"

    @patch("subprocess.run")
    def test_clone_with_branch(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(SourceFetcher, "_get_repo_info", return_value={}):
            fetcher = SourceFetcher(work_dir=tmp_path)
            result = fetcher._clone_git(
                "https://github.com/owner/repo.git", branch="main"
            )
        assert result["success"] is True
        call_args = mock_run.call_args[0][0]
        assert "-b" in call_args
        assert "main" in call_args

    @patch("subprocess.run")
    def test_clone_timeout(self, mock_run, tmp_path):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired("git", 1)
        fetcher = SourceFetcher(work_dir=tmp_path)
        result = fetcher._clone_git("https://github.com/owner/repo.git")
        assert result["success"] is False
        assert "timed out" in result["error"]

    @patch("subprocess.run")
    def test_clone_error(self, mock_run, tmp_path):
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(
            1, "git", stderr="fatal: not a repo"
        )
        fetcher = SourceFetcher(work_dir=tmp_path)
        result = fetcher._clone_git("https://github.com/owner/repo.git")
        assert result["success"] is False
        assert "fatal" in result["error"]

    @patch("subprocess.run")
    def test_strips_git_prefix(self, mock_run, tmp_path):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        with patch.object(SourceFetcher, "_get_repo_info", return_value={}):
            fetcher = SourceFetcher(work_dir=tmp_path)
            fetcher._clone_git("git+ssh://github.com/owner/repo.git")
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "git"
        assert call_args[1] == "clone"


class TestSourceFetcherGetRepoInfo:
    def test_counts_files_and_languages(self, tmp_path):
        src = tmp_path / "repo"
        src.mkdir()
        (src / "main.py").write_text("print('hello')")
        (src / "utils.js").write_text("console.log('hi')")
        (src / "readme.txt").write_text("readme")

        fetcher = SourceFetcher(work_dir=tmp_path)
        info = fetcher._get_repo_info(src)

        assert info["files"] == 3
        assert info["languages"]["python"] == 1
        assert info["languages"]["javascript"] == 1

    def test_gets_git_info_without_git_dir(self, tmp_path):
        src = tmp_path / "repo"
        src.mkdir()

        fetcher = SourceFetcher(work_dir=tmp_path)
        info = fetcher._get_repo_info(src)

        assert "remote_url" not in info
        assert "commit" not in info
        assert info["languages"] == {}
        assert info["files"] == 0


class TestSourceFetcherCleanup:
    def test_removes_work_dir(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path / "work")
        assert (tmp_path / "work").exists()
        fetcher.cleanup()
        assert not (tmp_path / "work").exists()

    def test_cleanup_nonexistent(self, tmp_path):
        fetcher = SourceFetcher(work_dir=tmp_path / "nonexistent")
        fetcher.cleanup()  # should not raise


class TestFetchSource:
    def test_fetch_source_convenience(self, tmp_path, monkeypatch):
        with patch.object(
            SourceFetcher, "fetch", return_value={"success": True, "path": "/tmp"}
        ):
            result = fetch_source("https://github.com/owner/repo.git", cleanup=True)
        assert result["success"] is True
