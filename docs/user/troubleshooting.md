# Troubleshooting

## The UI loads but nothing happens

**Symptom:** the page renders, but every action fails.

1. Check the API: `curl http://127.0.0.1:3137/api/health`
   → `{"status":"ok", ...}` means the API is fine.
2. Check the footer: **MSF: offline** means Metasploit is not running.
   Recon still works; module execution does not.

---

## "msf unavailable" / 503 on attack endpoints

Metasploit's RPC daemon (`msfrpcd`) is not running or not reachable.

```sh
# container
docker compose logs h4k | grep msfrpcd
docker exec -it h4k_h4k bash -lc 'ss -lntp | grep 55553'

# host install
msfrpcd -a 127.0.0.1 -p 55553 -U msf -P h4k_msf_rocks -S true -f &
```

The client retries 10× with a 2 s sleep before giving up, so the first
failure takes ~20 s to surface. Set `MSF_HOST`/`MSF_PORT`/`MSF_PASSWORD` to
match your daemon.

**You do not need Metasploit** for recon, fingerprinting, CVE correlation, the
toolkit, SAST/SCA, fuzzing or the AI loop.

---

## Discovery finds 0 hosts

* `arp-scan` needs **root** (raw sockets). In a container, that means the
  container needs `--cap-add=NET_RAW --cap-add=NET_ADMIN` or
  `--network host`.
* On a host install: `sudo arp-scan --interface=wlp3s0 192.168.1.0/24`
* Wrong interface? h4k picks the default route interface; override it:
  `export H4K_NET_IFACE=wlp3s0`.
* Wi-Fi clients are invisible to ARP — use `-sT` style TCP discovery or check
  the router's client list.

---

## The scan returns nothing

* **Scope**: with an active engagement, hosts outside the CIDR list are
  skipped *and reported* in the log (`[-] <ip>: skipped (outside scope)`).
* **Depth**: `quick`/`standard`/`full` decides port breadth; a partial sweep
  is labelled `[coverage] PARTIAL SCAN`.
* **Mode**: `stealth` deliberately skips many probes.
* **Rate limiting**: the API allows 600 req/min per IP by default. A `429`
  means you are polling too fast; the UI backs off automatically.

---

## Autopilot refuses to start

```
{"detail":"autopilot requires an active engagement scope ..."}
```

Set one:

```sh
curl -X POST http://127.0.0.1:3137/api/session/scope \
  -H 'Content-Type: application/json' -d '{"engagement_id":"<id>"}'
```

`409` means a run is already active — stop it first with
`POST /api/autopilot/stop`.

---

## Attacks say "could not reach msfrpcd"

The Metasploit path is the only thing that fails. See the first section.

---

## "Metasploit database is NOT connected" in the container logs

The RPC daemon only exposes `db.*` methods once it has actually loaded the
database. If the daemon starts before the postgres cluster is reachable it
silently answers "Database Not Loaded" — and then **db_nmap finds nothing**,
which looks exactly like "the scanner is broken" (a scan of 127.0.0.1 comes
back with zero hosts even though the API is obviously running).

The entrypoint now handles this:

1. start the cluster and wait for it to accept connections,
2. copy the DB config to root (`msfrpcd` and `db_nmap` run as root),
3. start `msfrpcd`,
4. **ask the daemon over RPC whether the DB is loaded**, and restart it once
   if not.

Check it yourself:

```sh
docker exec h4k_h4k msfconsole -q -x 'db_status; exit'
# -> [*] Connected to msf. Connection type: postgresql.
```

If it says "not connected", something else on the host already owns the
Metasploit database port (`5433` by default). Change it:

```sh
docker compose run -d -e MSF_DB_PORT=5434 h4k
```

---

## A scan of my own machine returns zero hosts

That is the db_nmap symptom above (the Metasploit database was not loaded),
not a scanning bug. Verify with:

```sh
docker exec h4k_h4k msfconsole -q -x 'db_status; exit'
```

---

## Hydra finds nothing

* The wordlists live at `/opt/h4k/data/users.txt` and `passwords.txt` in the
  container, `h4k/data/` on a host install. They are small on purpose.
* Hydra needs raw sockets for some services → run as root.
* A service that is *not* password-guessable will not yield.

---

## The fuzzer reports nothing

* Fuzzing is opt-in and only against targets you own.
* The bundled target is `vulnlab` on `127.0.0.1:8080` (or `3138` in
  compose). Start it: `cd vulnlab && docker compose up -d`.
* A black-box signal (teardown/500/hang) is a **lead**, not a confirmed crash.
  Confirm it by replaying the input.

---

## Semgrep / osv-scanner / trivy missing

These are optional binaries installed in the container image. On a host
install, install them separately, or use the bundled regex heuristics — SAST
still works without Semgrep, it just finds fewer issues.

---

## SCA returns zero CVEs

Correct, not a bug: osv-scanner needs a **committed lockfile** to resolve
packages. A fresh clone without one honestly returns `packages: []`.

---

## The UI shows a stale page after an update

The console is plain HTML/JS; the browser may cache `app.js`. Hard-reload
(Ctrl+Shift+R). The static assets are served with a `?v=` cache-busting
parameter that changes with the release.

---

## Running the tests

```sh
make test           # unit + API (fast, offline)
make e2e            # Selenium browser suite (headless Chrome)
make lint           # black, ruff, isort, flake8, mypy, pylint, bandit
```

`make e2e` needs `chromium` + `chromedriver` on PATH and `selenium` in the
venv. Override the browser with `H4K_CHROME_BINARY` / `H4K_CHROMEDRIVER`.

---

## Sanity check: is the whole stack really working?

```sh
python3 scripts/sanity_check.py            # or: make sanity
```

It checks 16 things against a **running** deployment — API health, Metasploit
RPC, the web console and its bundle, the engagement lifecycle (create →
scope → scan → inventory → ingest), crown jewels → attack paths, ATT&CK
mapping, the fuzzing lab, and container-escape detection — and prints a
pass/fail report. Exit code is non-zero if anything failed, so it works as a
CI gate too.

```sh
H4K_LIVE=1 pytest tests/test_live_stack.py -v   # same checks, as pytest
```

Useful after an upgrade or a compose change: it catches the "everything
looks fine but the Metasploit database was never loaded" class of failure.

---

## Getting a clean log for a bug report

```sh
docker compose logs --tail 500 h4k > h4k.log
curl -s http://127.0.0.1:3137/api/health
```
