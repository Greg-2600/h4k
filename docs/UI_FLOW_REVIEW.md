# UI flow review — dashboard vs operator console

Reviewed by driving the live stack with `scripts/e2e_ui_flow.py` (Selenium,
headless Chrome) against the contrived `vulnlab` container (intentionally
buggy HTTP parser on `:3138`). Screenshots: `artifacts/ui-flow/`.

Flow exercised: **scope → scan → discovery → full fingerprint → fuzz →
session report**, plus a dashboard Recon inspection.

## The core problem: two products in one app

| | Dashboard (`/`) | Operator console (`/ops`) |
|---|---|---|
| Navigation | 6 workspaces: Discover, Recon, Exploit, Pivot, Persist, Score | 9 phases: Assets, Walk, Fuzz, Lab, AD, Telemetry, Nightly, Report, Settings |
| Discovery | Scan/Neighbors buttons + stepper | "Discover & Scan" + Local Network tab |
| Services | Recon table (empty in practice) | Service Map table |
| Findings | "Likely vulnerable" card | Findings phase/panel |
| Report | Score tab | Report phase |
| Target input | `#target` | `#target` (same id, different page) |

Both pages implement overlapping discover/recon/report flows with different
stores and different completion semantics. A user has to know which page owns
which result. This is the main source of clunkiness.

**Recommendation:** make the dashboard a read-only overview (scope, live
counts, next action) that links into the console, and keep all mutation
(scan, fingerprint, fuzz, findings, report) in one place. If the dashboard
must stay, move Discover/Recon into the console and make the dashboard cards
deep-link to the corresponding console phase.

## Issues found and fixed in this pass

| # | Issue | Impact | Fix |
|---|---|---|---|
| 1 | "Discover & Scan" button was dead: `launchScan()` dereferenced a removed `[data-obj="host"]` node | Core flow could not start from the console | Null-guarded the legacy highlight |
| 2 | Scan-type tabs and action-panel tabs lost their listeners when the panel re-rendered | "Local Network" silently ran an IP scan instead | Delegated tab handling to `document` |
| 3 | Console expected `job_id` from `/api/scan`, but the API returns `id` | Scan ran but the UI reported failure and never polled | Accept `job_id \|\| id` |
| 4 | Scan progress wrote to removed `#sp-stages` | First poll threw; progress stalled at 0% | Guarded the element |
| 5 | "Local Network" discovery hardcoded `192.168.1.0/24` | Never found Docker/VPN subnets | Derives the container's local /24 |
| 6 | Fingerprinting was blocked by the approval gate (internal fixed-argv probes hit `run_tool`) | Service map always empty under `H4K_APPROVAL_MODE=enforce` | `internal=True` bypass for h4k-built probes; operator commands still gated |
| 7 | Full-port nmap XML was truncated to the last 4 KB before parsing | Full scans always reported 0 hosts | `full_output=True` for XML consumers |
| 8 | "Full Port Scan" called `/api/scan` and never updated the Service Map | Button appeared to do nothing in the console | It now runs a full-port fingerprint and fills the table |

## Remaining clunkiness (not fixed)

1. **Dashboard Recon table stays empty** even when the console shows services
   and the session card says `4 hosts`. The two pages read different stores.
   This is the most visible symptom of the split described above.
2. **Scope lives only on the dashboard.** The console silently inherits the
   active engagement; if none is active, scan results appear but scope-gated
   actions differ. The console needs a scope chip/dropdown.
3. **Discovery output includes bogus hosts** (`1`, `2`) parsed from arp-scan's
   summary lines; they are filtered later by scope checks but show in the
   inventory list and look broken.
4. **Shared progress strip.** Discovery, fingerprint and scan reuse
   `#sp-strip`, so "done" can be overwritten by an auto-started fingerprint
   (the console auto-runs a common-port fingerprint after discovery).
5. **Stale "next" suggestion.** The dashboard's next-action bar can suggest
   `fuzz 127.0.0.1:8080` even though the live target is `vulnlab:3138`.
6. **Report cache.** Re-scanning the same target/depth returns `cached: true`
   with the old report; there is no visible "cached" badge, so an empty early
   scan looks like a failure.
7. **Hidden primary action.** The target form is behind "＋ Discover"; the
   "start here" card competes with the form and the action panel tabs.

## The Selenium script

`scripts/e2e_ui_flow.py` drives the real UI (no API shortcuts):

1. dashboard: create scope, full scan `vulnlab`, verify `done`, inspect Recon
2. console: expand Discover → IP/CIDR scan → Local Network discovery →
   full-port fingerprint (asserts port `3138`) → fuzz (`vulnlab:3138`,
   150 iterations, asserts a crash candidate) → download the session report
3. dashboard: Recon inspection (documents the empty-table gap)

Run against the deployed stack:

```sh
python scripts/e2e_ui_flow.py                # headless, screenshots in artifacts/ui-flow/
python scripts/e2e_ui_flow.py --headful      # watch it
python scripts/e2e_ui_flow.py --target 172.18.0.2 --iterations 500
```

Last run: **passed in 74s**, report `h4k-session-*.md` downloaded, fuzz found
a distinct `resource` crash candidate on vulnlab.
