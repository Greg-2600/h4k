# Tech debt & feature backlog

The list this session worked through, and what is still open. Items marked
**[done]** landed in the repo with tests; the rest are the next candidates.

---

## Tech debt

| # | Item | Why it matters | Status |
|---|---|---|---|
| TD-1 | **CVE matching was not banner-aware** — it matched on the *service name* (`ftp`), so a vsftpd **3.0.3** host was flagged with the **2.3.4 backdoor** CVE (critical false positive on a patched machine) | A tool that cries wolf is worse than one that says nothing. Now the version ranges are keyed by the *detected* product, an out-of-range version excludes the CVE, and a match we cannot rule out is marked `_version_verified: false` instead of being asserted | **[done]** (`cve_lookup.py`, `version_detector.py`, `tests/test_cve_lookup.py`) |
| TD-2 | **`find_exploits()` always returned nothing** — the module catalogue lives in `modules.exploits`, not the `module_types` dict the old code looked for | The platform could not suggest a single module. Now it reads the real catalogue and name-filters it (thousands of RPC calls → a handful) | **[done]** |
| TD-3 | **Auxiliary/post modules could not run** — the module type was hardcoded to `exploit` | Scanners (`ssh_enumusers`, `vsftpd_version`) were unreachable. Now the type follows the module path and `module.options`/`module.execute` go over raw RPC, with a pymetasploit3 fallback | **[done]** |
| TD-4 | **`AttackRequest` could not carry module options** (`USER_FILE`, `URI`, …) | A triage drawer could not tune a module. Now `options` is merged and filtered by the module's own option list | **[done]** |
| TD-5 | **The runtime data directory was resolved in two places** (`scan.py`, `engagement.py`) with different rules | They could disagree, and the tests had to patch a private attribute. Now one module (`paths.py`) owns the resolution, including `$H4K_DATA_DIR` | **[done]** |
| TD-6 | **No "what can this instance do?" report** — a missing tool or a Metasploit without a database failed *silently* (a scan of localhost returned zero hosts) | The operator could not tell a broken scan from an empty network. Now `GET /api/capabilities` reports tools, Metasploit/DB state, storage and warnings; the UI shows a badge and `scripts/sanity_check.py` asserts on it | **[done]** |
| TD-7 | **The capabilities report was slow** (a dozen sequential `--version` probes) and re-probed on every poll | Fixed with parallel probes and a 60 s cache keyed by the sandbox flag | **[done]** |
| TD-8 | **`GET /api/graph` returned 500** whenever a scope was active (`in_scope()` called with one argument instead of two) | The Network Graph broke exactly when an engagement was armed | **[done]** |
| TD-9 | **The Report page threw `ReferenceError: renderReportPreview`** on every visit (the function was called but never written) | Found by the new Selenium suite — the page was dead for everyone | **[done]** |
| TD-10 | **The scope picker was only populated after a password attack** | The header said "scope: none" on a fresh load even with an engagement armed | **[done]** |
| TD-11 | **No schema migrations** — `engagements.db` evolves by `CREATE TABLE IF NOT EXISTS` only | Column changes need a manual migration. Needs a `schema_version` table + runner | open |
| TD-12 | **Global mutable `app_state`** (module-level singletons) | Harder to run tests in parallel, awkward to reason about. Wants a small dependency container | open |
| TD-13 | **The Docker build is slow** — an unpinned `semgrep` made pip backtrack through dozens of 70 MB wheels | Pinned `semgrep==1.182.0`; a base/app layer split would help more | partly **[done]** |
| TD-14 | **`/api/health` is too thin** — it says "ok" while the Metasploit DB is dead | `/api/capabilities` now covers it; `/api/health` should probably gain a `ready` flag | open |
| TD-15 | **The lab tooling is undocumented and untested** (`scripts/transmission_rpc.py`, `torrent_seeder.py`, `torrent_tracker.py`) | They are the reason the Transmission chain works; they need docs + unit tests | **[done]** (`tests/test_lab_scripts.py`: bencode, RPC retry, seeder piece-serving, tracker/sanity client/report) |
| TD-16 | **No per-tool rate limits or job quotas** — one operator can queue 50 scans | `H4K_RATE_LIMIT` exists for HTTP but not for tool invocations | open |

---

## Features

| # | Item | Status |
|---|---|---|
| F-1 | **Crown jewels** — declare the objectives that matter, with a business value | **[done]** |
| F-2 | **Attack paths** — scored, evidence-backed paths from footholds to the crown jewels | **[done]** |
| F-3 | **ATT&CK mapping + detection guidance** per finding | **[done]** |
| F-4 | **Capability/readiness report** (`/api/capabilities`) + UI badge | **[done]** |
| F-5 | **Attack-path export** (`?fmt=md`) for delivery notes | **[done]** |
| F-6 | **Engagement snapshot export/import** (`/export`, `/import`) — portable, scope-checked | **[done]** |
| F-7 | **Selenium E2E suite** (21 tests) with a sandbox-mode API | **[done]** |
| F-8 | **Full documentation set** (`docs/`, 18 files) | **[done]** |
| F-9 | **Sandbox mode** — deterministic, offline, zero-touch mode for demos/CI/E2E | **[done]** |
| F-10 | **`labs/transmission-rce`** — a lab that demonstrates unauthenticated RPC → file write → RCE | **[done]** |
| F-11 | **Wordlist management** — list the bundled lists *and* the distro ones (nmap 5 k, seclists, rockyou) so password attacks are not limited to 74 words | partly **[done]** (discovery in `/api/capabilities`; the selector UI is open) |
| F-12 | **Scheduled scans** (cron-like) | open |
| F-13 | **Attack-surface score per host** — one number that says "this host is the interesting one" | open |
| F-14 | **Job dashboard** — every job family in one list with cancel/retry | open |
| F-15 | **Snapshot import UI** — drag a `.h4k` snapshot into the UI | open |
| F-16 | **A "what changed since last run" diff** for engagements | open |
| F-17 | **Plugin interface** for custom tools and report sections | open |
| F-18 | **Visual regression** (screenshots of the key pages) in CI | open |

---

## Next three (recommended order)

1. **F-11 + TD-16** — make password attacks actually useful (wordlist picker)
   and stop one operator from queueing 50 scans.
2. **TD-11 + TD-12** — schema migrations and a dependency container: the two
   things that will hurt the most as the engagement store grows.
3. **F-13** — an attack-surface score; it is the piece that turns a list of
   hosts into a work queue.
