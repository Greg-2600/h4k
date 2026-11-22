# UI flow review — dashboard vs operator console

Reviewed by driving the live stack with `scripts/e2e_ui_flow.py` (Selenium,
headless Chrome) against the contrived `vulnlab` container (intentionally
buggy HTTP parser on `:3138`). Screenshots: `artifacts/ui-flow/`.

Flow exercised: **scope → scan → discovery → full fingerprint → fuzz →
session report**, plus dashboard Recon verification.

## Single UI (resolved)

There is now **one page and one navigation**: `/`. The console's non-kill-chain
phases live in an **Operations** workspace beside Discover/Recon/Exploit/Pivot/
Persist/Score:

| Operations tab | Contents |
|---|---|
| Fuzz | signal-guided fuzzing, crash candidates |
| Labs | benign traffic kit + IoT/OT probes |
| AD | domain policy, users, audit, roast/spray |
| Telemetry | ingest summary, detections, simulate/reset |
| Nightly | schedules and run history |
| Report | findings ledger, approvals, attack paths, session report |
| Settings | auth keys and console preferences |

`/ops` is no longer a second app: it **307-redirects** to `/?tab=ops`, and the
console document is only served as `?embed=1` inside the workspace. The embed
inherits the dashboard theme and fonts, so it reads as one surface. A future
native port could drop the internal iframe, but users no longer choose between
two products.

## Issues found and fixed in this pass

| # | Issue | Impact | Fix |
|---|---|---|---|
| 1 | "Discover & Scan" was dead: `launchScan()` dereferenced a removed `[data-obj="host"]` node | Console flow could not start | Null-guarded the legacy highlight |
| 2 | Scan-type and action-panel tabs lost listeners when the panel re-rendered | "Local Network" silently ran an IP scan | Delegated tab handling to `document` |
| 3 | Console expected `job_id` from `/api/scan`; the API returns `id` | Scan ran but the UI reported failure | Accept `job_id \|\| id` |
| 4 | Scan progress wrote to removed `#sp-stages` | First poll threw; progress stalled | Guarded the element |
| 5 | "Local Network" discovery pinned to `192.168.1.0/24` | Never found Docker/VPN subnets | Derives the container's local /24 |
| 6 | Approval gate blocked internal fixed-argv probes | Service map always empty under `enforce` | `internal=True` for h4k-built probes |
| 7 | Full-port nmap XML truncated to 4 KB before parsing | Full scans always reported 0 hosts | `full_output=True` for XML consumers |
| 8 | "Full Port Scan" called `/api/scan` and never filled the Service Map | Button appeared inert | It now runs a full-port fingerprint |
| 9 | Scope picker existed but its init was nested inside the password-attack poller | Console showed no scope and could not switch it | Initialised on `DOMContentLoaded` |
| 10 | IPv6 NDP parser matched the last digit of IPv4 addresses | Phantom hosts `1`, `2` in discovery | Requires a real IPv6 address |
| 11 | Partial sweeps (auto-scan, recheck) deleted all services for a host before inserting | Wiped deep-fingerprint results (e.g. 3138) | Merge on partial sweeps; replace only on complete |
| 12 | Next-move hardcoded `fuzz 127.0.0.1:8080` | Suggested a target that is not in the engagement | Uses a discovered host/service |
| 13 | Cached scan reports looked identical to fresh ones | An old empty scan looked like a failure | Status shows `done · cached` |

Dashboard Recon now displays the console's fingerprint results (the earlier
empty table was issue #11 plus a load race), verified by the Selenium flow:
`3 hosts · 6 services` including `172.18.0.2:3138`.

## Remaining clunkiness (not fixed)

1. **Two products in one app** — see the recommendation above.
2. **Hidden primary action** — the target form is behind "＋ Discover"; the
   "start here" card and the form compete for the same attention.
3. **Shared progress strip** — discovery, fingerprint and scan reuse
   `#sp-strip`, and the console auto-runs a common-port fingerprint after
   discovery, so "done" can be overwritten by the next stage.
4. **Stale report cache** — re-scanning the same target/depth returns the
   cached report; there is a badge now but no way to force a refresh from
   the scan row.
5. **Weak next moves** — the queue is dominated by default-credential
   suggestions for every host; severity/exposure ranking would be better.

## The Selenium script

`scripts/e2e_ui_flow.py` drives the real UI (no API shortcuts):

1. dashboard: create scope, full scan `vulnlab`, verify `done`, inspect Recon
2. console: verify the scope picker shows the active engagement → IP/CIDR
   scan → Local Network discovery → full-port fingerprint (asserts `3138`)
   → fuzz `vulnlab:3138` (asserts a distinct crash) → download the report
3. dashboard: Recon must show `3138` from the shared neighbor store

Run against the deployed stack:

```sh
python scripts/e2e_ui_flow.py                # headless; screenshots in artifacts/ui-flow/
python scripts/e2e_ui_flow.py --headful      # watch it
python scripts/e2e_ui_flow.py --target 172.18.0.2 --iterations 500
```

Last run: **passed in 99s**, scope picker selected, discovery returned only
real hosts, service map showed `3138`, fuzz produced a `resource` crash
candidate, and the session report downloaded.
