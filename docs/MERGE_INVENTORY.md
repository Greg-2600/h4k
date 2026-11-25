# h4k branch reconciliation inventory (2026-11-21)

Snapshot for deciding how to reconcile local `main` with `origin/main`.
No code was changed to produce this document.

- Merge base: `ce25130` (toolkit: AD Kerberos roasting)
- Local `main`: `dc8a78a` — 65 commits after base
- `origin/main`: `3f29632` — 128 commits after base
- Safety refs: branch `backup/pre-sync-20261121`, tag `backup-h4k-pre-sync`

## Headline

| Metric | Value |
|---|---|
| Files changed locally | 164 |
| Files changed on origin | 338 |
| Files changed on **both** sides | **115** |
| Files changed only locally | 49 |
| Files changed only on origin | 223 |
| Local commits already in origin (patch-id match) | **53 of 65** |
| Local commits **not** in origin | **9 features + 2 docs** |
| Net-new origin commits | 75 |

The divergence is not 65-vs-128 independent lines of work: **53 of the 65
local commits are already upstream** (merged via PRs with different SHAs).
The real porting surface is the 9 unique feature commits below. What makes
them expensive is that both sides independently added the same modules
(`auth`, `sandbox`, `engagement`, `attack_paths`, `propagate`,
`version_detector`, `nuclei`) with different designs.

## Overlapping modules (lines: local vs origin)

Only modules changed on both sides and with different sizes:

| Module | Local | Origin |
|---|---:|---:|
| `api/routers/scan.py` | 3564 | 5016 |
| `api/services/scan_pipeline.py` | 1103 | 1111 |
| `api/services/engagement.py` | 920 | 1382 |
| `api/services/auth.py` | 783 | 52 |
| `api/services/toolkit.py` | 562 | 551 |
| `api/routers/source.py` | 548 | 936 |
| `api/services/sandbox.py` | 525 | 432 |
| `api/services/attack_paths.py` | 475 | 308 |
| `api/services/version_detector.py` | 381 | 440 |
| `api/services/sca.py` | 288 | 311 |
| `api/services/attack.py` | 283 | 464 |
| `api/services/propagate.py` | 270 | 322 |
| `api/services/discovery.py` | 258 | 275 |
| `api/routers/engagement.py` | 256 | 756 |
| `api/services/ai.py` | 235 | 190 |
| `api/services/__init__.py` | 234 | 166 |
| `api/services/msfrpc.py` | 197 | 324 |
| `api/services/nuclei.py` | 179 | 311 |
| `api/services/cve_lookup.py` | 168 | 190 |
| `api/routers/net.py` | 114 | 190 |
| `api/services/ai_loop.py` | 113 | 107 |

Also overlapping but similar in size: `scan_pipeline`, `toolkit`,
`version_detector`, `ai_loop` — these are mergeable rather than
winner-takes-all.

`auth` and `sandbox` are **not the same feature**, despite the filename:

- Local `auth.py` (783 lines) is the full access-control layer (API keys,
  roles, OIDC, signed sessions, rate limits) from the local roadmap.
- Origin `auth.py` (52 lines) is API-key authentication only.
- Local `sandbox.py` (525 lines) runs allowlisted tools under rlimits.
- Origin `sandbox.py` (432 lines) provides offline stand-ins for tools
  ("sandbox mode"), i.e. a different concept under the same name.

## The 9 local-unique feature commits

| Commit | Subject | Files | Files also changed on origin |
|---|---|---:|---:|
| `dbeff95` | recon page flow — neighbor discovery, fingerprint map, neighbors DB | 42 | 40 |
| `ebc0e92` | operator surface, identity, sandbox, lab systems, sidecars | 47 | 12 |
| `58e439c` | frame untrusted evidence in LLM prompts | 8 | 6 |
| `64ad2ad` | evidence-bound finding ledger with retest verdicts | 15 | 11 |
| `a63dca1` | attack paths to objectives and a coverage ledger | 15 | 14 |
| `3ce38cf` | approval gate for sandbox and toolkit execution | 19 | 14 |
| `a836224` | target noise governor and AI budgets | 22 | 16 |
| `14a6fdc` | build and verify the heavy sidecars | 19 | 7 |
| `dc8a78a` | compose works on Docker Desktop | 2 | 2 |

Two further unique commits should **not** be ported:

- `1d17510` adds an older `CURRENT_STATE.md`; origin already has a newer one.
- `185f52e` records live-target findings (IPs, RCE details). Origin's newer
  policy keeps engagement notes out of the repo; it also conflicts with it.

## Local-only assets (no origin equivalent)

- Sidecars: `adlab/`, `iotlab/`, `sandbox-runner/`, `telemetry-agent/`,
  `bloodhound/`, plus their compose profiles.
- Routers: `ad`, `approvals`, `auth` (local variant), `automation`,
  `bloodhound`, `findings`, `lab`, `noise`, `sandbox`, `telemetry`.
- Services: `ad_attacks`, `ad_audit`, `ai_budget`, `approval`,
  `bloodhound_ce`, `findings`, `iot_ot`, `lab_traffic`, `nightly`, `noise`,
  `telemetry`, `untrusted`, `wire`.
- Tests for all of the above (`test_untrusted`, `test_telemetry`,
  `test_noise_budget`, `test_nightly`, `test_lab_traffic`, `test_iot_ot`,
  `test_findings`, `test_bloodhound_ce`, `test_approval`, `test_ad_attacks`,
  `test_a11y`).

## Origin-only assets (not in local)

- 46 new services: `attck`, `auto_scan`, `blue_team`, `capabilities`,
  `cert_inventory`, `ci_gate`, `container_fuzz`, `dast_spider`, `firetv`,
  `flag_paths`, `flags`, `fuzz_profiles`, `fuzz_shard`, `graph_canvas`,
  `hygiene`, `ipv6_discovery`, `jwt_tester`, `kerberos`, `kev`,
  `kubelet_audit`, `loot_vault`, `merged_report`, `multilang_sast`,
  `next_move`, `nse_suggest`, `passive_sniff`, `pdf_report`, `privesc`,
  `privesc_suggest`, `ratefuzz`, `rbac_audit`, `reachability`, `rescan`,
  `sanitizer_diff`, `sarif_exchange`, `sast_delta`, `secret_baseline`,
  `spray_guard`, `ssrf_pack`, `stateful_fuzz`, `supervisor`, `suppress`,
  `taint_pack`, `tls_fingerprint`, `verify_fix`, `watch`.
- `labs/transmission-rce/`, 47 e2e tests, `docs/dev/`, `docs/user/`,
  `docs/security/`, CODEOWNERS/CONTRIBUTING/SECURITY and CI files.

## Decision matrix (provisional)

| Area | Recommendation |
|---|---|
| `engagement`, `propagate`, `attack_paths` | Take origin's larger base, then port local scope-enforcement/objective features on top |
| `auth` | Choose one: local (roles/OIDC/limits) or origin (API key only). Porting local's operator surface pulls local auth in |
| `sandbox` | Keep both concepts but rename one (local = tool executor; origin = offline sandbox mode) |
| `untrusted`, `findings`, `approval`, `noise`, `ai_budget`, `nightly`, `telemetry`, `ad_*`, `iot_ot`, `lab_traffic`, `bloodhound*`, `wire` | Local-only; port as-is |
| Sidecar directories + compose profiles | Local-only; port as-is |
| Recon page flow (`dbeff95`) | Last and hardest: 40 of 42 files overlap origin's range-scan/dashboard work; needs a UI decision |
| `scan.py`, `main.py`, `schemas.py`, `web/*` | Merge by hand per feature; never take one side wholesale |

## Suggested sequence

1. Branch from `origin/main` (`sync/port-local-features`).
2. Port standalone features first: `untrusted` (58e439c) → `findings`
   (64ad2ad) → `attack_paths` (a63dca1) → `approval` (3ce38cf) → `noise` +
   `ai_budget` (a836224).
3. Split `ebc0e92` by feature; port sidecars/labs/telemetry/AD/BloodHound
   parts, but do **not** replace origin's `auth`/`sandbox` wholesale.
4. Port `14a6fdc` + `dc8a78a` sidecar build/compose fixes.
5. Port the recon flow (`dbeff95`) last, after the UI/scan router merge is
   stable.
6. Run the full suite and sidecar smoke tests at every step; keep
   `backup/pre-sync-20261121` until the port is pushed.


---

## Outcome (2026-11-21)

Executed on branch `sync/converge` (origin/main as the base):

- Stage 1: local-only services/routers/sidecars ported; sandbox tool executor
  renamed `sandbox_exec.py`; untrusted framing, AI budget, approval gate,
  source budget endpoints and the session finding ledger integrated.
- Stage 2: the local UI is served as `/ops` (ops.html/ops.js/ops.css) beside
  origin's dashboard, linked from the nav.
- Stage 3: objectives unified onto `crown_jewels` (kind/criticality +
  migration), coverage ledger, `attack_plan.py`, objective/coverage/paths API
  and session-report sections.
- Stage 4: sidecars moved onto origin's `h4k-net` bridge with service DNS;
  adlab reachable at 172.30.0.10; impacket 0.13.1 pinned in the image.
- Stage 5: full auth layer (roles/OIDC/rate limits) with legacy H4K_API_KEY
  compatibility.

Verification: image builds, stack healthy (h4k + vulnlab), `/` and `/ops`
return 200, sandbox reports `mode=sidecar`, telemetry ingests, adlab policy
read succeeds. Suite: 1806 passed, 3 skipped; the only 3 failures
(fuzz-shard RST fixture, two privesc host-tool checks) also fail on
origin/main on macOS and pass on Linux CI.


## Recon-flow follow-up (2026-11-21)

The local recon commit (`dbeff95`) is already converged: origin's
`services/discovery.py` has the same public functions and the same 60-entry
OUI table, and origin's scan router provides `/api/neighbors`,
`/api/neighbors/scan|status|jobs`, `/api/neighbors/fingerprint(+/status|results)`
and `/api/graph` with the same job shape the local UI polls. The local recon
UI (Local Network tab, Service Map, full-port-scan flow) is preserved at
`/ops`. No duplicate backend was added.

Live check on the converged stack: `/api/neighbors`, `/api/graph` and
`/api/neighbors/jobs` return 200; `POST /api/neighbors/scan` starts a job;
`/ops` returns 200.
