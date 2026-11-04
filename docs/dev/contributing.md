# Contributing

## Setup

```sh
git clone https://github.com/Greg-2600/h4k.git
cd h4k
python3 -m venv .venv && source .venv/bin/activate
make setup          # pip install -r requirements-dev.txt
```

`make setup` installs the runtime deps **and** the toolchain (black, ruff,
isort, flake8, mypy, pylint, bandit, pytest, pytest-cov).

## The loop

```sh
make fmt      # black + isort
make fix      # ruff --fix
make lint     # everything; all must pass
make test     # unit + API
make e2e      # Selenium (needs chromium + chromedriver)
make coverage # coverage report (90% gate)
```

**All linters must pass before you push.** CI runs the same commands.

## Style rules the repo enforces

| Rule | Why |
|---|---|
| `black` + `isort` (line length 88) | No formatting debates in review |
| `ruff` with `E,F,W,I,B,UP,C4,SIM,RUF,ASYNC` | Catches bugs early |
| `mypy` with `disallow_untyped_defs` | Public functions are typed |
| `pylint` (score ≥ 7.0) | Catches smells |
| `bandit` | No obvious security holes; `# nosec` needs a **rule id + rationale** |
| `flake8` | Compatibility net |

## Conventions

* **Routers stay thin.** Parse, delegate, return. No business logic.
* **Services never import FastAPI.** Plain data in, plain data out.
* **Every external call has one seam.** `ToolkitRunner.run_tool`,
  `MsfClient.execute`, `NeighborFinder.discover`. Tests replace exactly one.
* **Aggressive behaviour is opt-in** and defaults to off.
* **Scope is enforced in the store**, never only in the UI.
* **No fabricated findings.** If the tool did not say it, h4k does not print it.
* **Comments explain *why*.** The code already says what.

## Tests

* New behaviour → a unit test.
* New/changed endpoint → an API test (`TestClient`).
* New/changed UI → a Selenium test in `tests/e2e/`, targeting `data-testid`
  hooks.
* Tests must be offline. Never require a live Metasploit or the network.
  The two exceptions are opt-in and skipped by default: `H4K_LIVE=1 pytest
  tests/test_live_stack.py` (live API) and `H4K_LIVE_E2E=1` +
  `tests/e2e/test_live_flow.py` (live browser flow against a target you own,
  recon only).

```sh
pytest -k "my_feature" -v
pytest --cov --cov-report=term-missing
```

## Adding a UI element

1. Give it a stable `data-testid="kebab-name"`.
2. Keep the id stable too (`#btn-thing`) — other code may reference it.
3. Add a `tests/e2e/` test that exercises it.
4. Never use `window.prompt`/`alert` for input — they are untestable and
   block the browser. Use a real form.

## Committing

Only commit when asked. Small, focused commits with a clear message:

```
feat(engagement): crown jewels + attack-path engine
fix(ui): report preview threw ReferenceError on page switch
test(e2e): selenium suite for crown jewels and ATT&CK panel
```

Never commit secrets, real credentials, scan data or the `h4k_data` volume.
`.gitignore` already covers `.venv`, `__pycache__`, fuzz artifacts and the
runtime data directory.

## Pull requests

1. `make lint && make test && make e2e` all green.
2. Update `AGENTS.md` (service map, API surface, gotchas) if you changed
   structure.
3. Update `RELEASE_NOTES.md` for user-visible changes.
4. Update the docs under `docs/` if behaviour changed.
