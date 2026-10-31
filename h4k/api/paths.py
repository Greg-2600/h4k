"""Where h4k keeps its runtime data.

One place decides what the data directory is, so the API, the engagement
store and the tests can never disagree about it.

Resolution order:
  1. ``$H4K_DATA_DIR`` (explicit override -- used by the test suite and by
     anyone running several instances side by side)
  2. ``/opt/h4k/data``  (the container image)
  3. ``<repo>/h4k/data`` (a host checkout)
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

ENV_VAR = "H4K_DATA_DIR"
CONTAINER_DATA = Path("/opt/h4k/data")
REPO_DATA = Path(__file__).resolve().parent.parent / "data"

# Wordlists the toolkit can use. The bundled ones are small on purpose; the
# operator can point at any file, and the common distro lists are picked up
# automatically when they exist.
WORDLISTS: dict[str, str] = {
    "users": "users.txt",
    "passwords": "passwords.txt",
    "web-words": "web-words.txt",
}


def data_dir() -> Path:
    """The runtime data directory (created if it does not exist)."""
    override = os.environ.get(ENV_VAR, "").strip()
    if override:
        path = Path(override)
    elif CONTAINER_DATA.is_dir():
        path = CONTAINER_DATA
    else:
        path = REPO_DATA
    with contextlib.suppress(OSError):
        path.mkdir(parents=True, exist_ok=True)
    return path


def data_file(name: str) -> Path:
    """A file inside the runtime data directory."""
    return data_dir() / name


def wordlist_path(kind: str) -> Path:
    """Path to a bundled wordlist ('users', 'passwords', 'web-words')."""
    return data_file(WORDLISTS.get(kind, f"{kind}.txt"))


def external_wordlists() -> dict[str, str]:
    """Wordlists shipped by other tools that we can reuse.

    nmap ships a 5 000-entry password list; Kali ships seclists. Both are far
    more useful than the bundled 74-word starter list, so we pick them up when
    they are installed.
    """
    found: dict[str, str] = {}
    candidates = {
        "nmap-passwords": "/usr/share/nmap/nselib/data/passwords.lst",
        "nmap-usernames": "/usr/share/nmap/nselib/data/usernames.lst",
        "seclist-passwords": "/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt",
        "seclist-users": "/usr/share/seclists/Usernames/Names/names.txt",
        "rockyou": "/usr/share/wordlists/rockyou.txt",
    }
    for name, path in candidates.items():
        if Path(path).is_file():
            found[name] = path
    return found


def is_writable(path: Path) -> bool:
    """True when we can actually create files in `path`."""
    with contextlib.suppress(OSError):
        return os.access(path, os.W_OK)
    return False
