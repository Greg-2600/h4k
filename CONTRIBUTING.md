# Contributing

The full guide lives at [docs/dev/contributing.md](docs/dev/contributing.md).
The short version:

```sh
make setup          # venv + toolchain
make lint           # everything must pass before you push
make test           # unit + API (offline)
make e2e            # Selenium (needs chromium + chromedriver)
make coverage       # 90% gate
```

Small, focused commits. Never commit secrets, scan data, or `h4k_data`.
Update `AGENTS.md`, `RELEASE_NOTES.md`, `ROADMAP.md` and `docs/` when
behaviour changes.
