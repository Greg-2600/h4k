# Testing guide

Three layers, each with a different job.

| Layer | Where | Needs | Runtime |
|---|---|---|---|
| **Unit** | `tests/test_*.py` | nothing | seconds |
| **API** | `tests/test_engagement_api.py`, `tests/test_api.py` | nothing (TestClient + fake MSF) | seconds |
| **E2E** | `tests/e2e/` | Chrome/Chromium + chromedriver | ~1 minute |

```sh
make test     # unit + API
make e2e      # Selenium
make lint     # black ruff isort flake8 mypy pylint bandit
make coverage # pytest + coverage (90% gate)
```

---

## Unit tests

Plain pytest. No network, no daemon, no fixtures beyond `tmp_path`.

```sh
pytest tests/test_sandbox.py -v
pytest -k "attack_paths" -v
```

House rules:

* Tests must never require a live Metasploit or a real network.
* Anything that shells out is stubbed (`no_subprocess` fixture, fake `Msf`).
* Files that touch the filesystem use `tmp_path` — never the repo's `data/`.

---

## API tests

`fastapi.testclient.TestClient` against the **real** app, with the MSF client
replaced and the lifespan neutralized:

```python
@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("H4K_REFRESH_CVE", "0")
    monkeypatch.setenv("H4K_DATA_DIR", str(tmp_path))
    import app_state
    import main as main_module

    app_state.msf_client = FakeMsf()

    @asynccontextmanager
    async def _noop(_app):
        yield

    main_module.app.router.lifespan_context = _noop
    return TestClient(main_module.app)
```

This pins the **HTTP contract**: status codes, payload shapes, and scope
enforcement (400 for out-of-scope, 404 for unknown engagement, …).

---

## E2E (Selenium)

`tests/e2e/` drives a **real browser** against a **real API process**.

```
tests/e2e/
├── conftest.py                    API subprocess + driver + page fixtures
├── helpers.py                     wait_for / click / fill / go_to
├── test_ui_smoke.py               boot, navigation, scope picker, report page
├── test_crown_jewels_attack_paths.py
├── test_attck_panel.py
└── test_autopilot_walk.py
```

### Sandbox mode

The E2E suite runs the API with `H4K_SANDBOX=1`:

* `NeighborFinder` returns a fixed 3-host lab estate,
* `ToolkitRunner.run_tool` returns canned nmap XML / hydra output,
* the Metasploit client is a fake that **refuses** to "exploit" anything.

Everything above the tool boundary — API, parsers, engagement store,
attack-path engine, UI — is the real code. Nothing touches the network.

### Fixtures

| Fixture | Scope | What it gives you |
|---|---|---|
| `api_server` | session | A live API on a free port, in sandbox mode, isolated data dir |
| `api` | session | Tiny JSON HTTP client for assertions/setup |
| `driver` | session | Headless Chrome (shared, for speed) |
| `page` | function | A fresh page; **fails the test on uncaught JS errors** |
| `seeded` | function | A seeded engagement (hosts, creds, crown jewel) + reloaded page |

### Writing a test

```python
from .helpers import all_of, click, fill, go_to, wait_text, wait_visible


def test_add_crown_jewel_through_the_form(page, seeded):
    go_to(page, "report")
    click(page, "compute-paths")
    wait_visible(page, "crown-list")
    fill(page, "crown-host", "10.10.10.9")
    fill(page, "crown-label", "Jump host")
    click(page, "add-crown")
    wait_text(page, "crown-list", "Jump host")
```

Rules of thumb:

* Target elements by **`data-testid`**, not CSS classes — classes churn, ids
  do not.
* Use `wait_text` / `wait_visible` instead of `time.sleep`.
* `wait_text` reads `textContent`, so it also works for panes that are
  currently hidden (e.g. the activity log while the Report tab is open).
* The `page` fixture fails the test if the browser logged an uncaught
  JavaScript error or a 5xx. That is how the missing
  `renderReportPreview()` bug was caught.

### Requirements

```sh
# Arch
sudo pacman -S chromium chromedriver
# Debian/Ubuntu
sudo apt install chromium chromium-driver
pip install selenium
```

Override the binaries when needed:

```sh
H4K_CHROME_BINARY=/usr/bin/google-chrome \
H4K_CHROMEDRIVER=/usr/bin/chromedriver \
make e2e
```

---

## Live-stack test

`tests/test_live_stack.py` runs the same checks as
`scripts/sanity_check.py` against a **running** deployment. It is opt-in
because it needs the stack up:

```sh
docker compose up -d
H4K_LIVE=1 pytest tests/test_live_stack.py -v
```

It proves the parts unit tests cannot: Metasploit's RPC daemon, the real
database, the web console being served, a real scan producing an inventory,
and the attack-path/ATT&CK engines working on live data.

---

## Coverage

`make coverage` enforces a **90%** gate (`pyproject.toml`). The
`h4k/api/services/msfrpc.py` transport is omitted — it is exercised against
a fake, not a daemon.

---

## CI

`.github/workflows/ci.yml` runs two jobs:

* `lint-test` — lint + pytest + coverage gate.
* `e2e` — installs Chrome via `browser-actions/setup-chrome`, then `make e2e`.

The E2E job is hermetic: sandbox mode means no network access is required
beyond installing the browser.
