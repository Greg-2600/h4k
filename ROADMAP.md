# h4k roadmap

Updated 25 November 2026 from `main` at `370c9a8`. Sizes are rough: S is a day or two, M is a week or two, L is a month or more.

## Vision

h4k is a single operator, containerized security analysis lab that takes a target from recon to evidence. It drives Metasploit over RPC and pairs that with SAST, SCA, fuzzing, triage and local AI assistance. Every aggressive step stays opt in and checked against a declared engagement scope. The goal is a tool a student can run in a weekend and an analyst can trust enough to hand a report to a defender.

## Current state

- **Working product.** Recon, scan, CVE and credential checks, engagement graph, attack paths, ATT&CK mapping, SAST and SCA, fuzzing with crash dedup, AI assist and a browser console all ship. Sandbox mode keeps demos and CI offline.
- **Recent merges.** Git log confirms SMB shares (#28), shared corpus (#72), Shodan and Censys import (#42), mDNS and SSDP assets (#40), scheduled rescans (#26), DAST spider (#24), stateful fuzz (#77), multilang SAST (#93) and the native Operations UI (#99 to #101) on `main`.
- **Tests and CI.** The latest `main` CI run (`45565074408`) had lint green and 1828 unit and API tests passing with 7 skipped. The coverage report printed 89.98 percent against a 90 percent gate while the job still showed green. The browser job collected 79 tests, passed 75, skipped 3 live target tests and failed `test_canvas_renders_nodes` on a 30 second wait. The previous `main` run was green.
- **Backlog hygiene.** There are no open issues. There are 30 open PRs, numbered #30 through #81, and all are flagged conflicting. Their last updates are from 5 November 2026.
- **Release.** `h4k/api/main.py` reports version 1.0.0. `scripts/release.sh` builds and tags the image, and `qualify.yml` runs a weekly and on demand live stack workout as an advisory check.

## Delivered (verified in git log)

- [x] Tier 1 polish: sanitizer first findings, real crash minimization, crash dedup, seeded mutation engine, merged report and AI hookup in the UI.
- [x] Tier 2 source work: SCA fixture with a committed lockfile, SBOM download, custom Semgrep rules, license and secret scanning, offline rule bundle.
- [x] Tier 3 analysis: AI full loop, local TLS lab, OSS Fuzz style runner and supply chain map with dependency graph reachability.
- [x] Tier 4 operator work: persistent engagement store, credential propagation, attack paths, ATT&CK techniques and detection guidance.
- [x] Lab toolkit: ZAP, John, aircrack, tshark, NSE, container escape, lateral movement, database interrogation, Fire TV, container fuzz and flag paths.
- [x] Backlog 1 to 28: graph canvas (#22), Nuclei (#23), DAST spider (#24), rescan digest (#26), SMB shares (#28), hygiene (#25), NSE suggest (#27), Kerberos (#29), spray guard (#31), vault (#33), PDF report (#35), TLS and IPv6 (#37, #39, #41), KEV (#44), suppress (#46), privesc (#48), kubelet and RBAC (#58, #60), SSRF (#63), JWT (#71), sanitizer diff (#74), rate aware fuzz (#78), sharding (#80), SARIF (#82), taint (#83), secrets (#84) and reachability (#85).
- [x] Backlog 57, 61 and 63 to 66: corpus (#72), stateful fuzz and auth profiles (#77), CI gate (#87), delta (#88), NOSAST (#89), verify fix (#91), palette (#92) and multilang SAST (#93).
- [x] Infrastructure: CI with lint and coverage, Selenium suite, sandbox mode, capability report, passive auto scan, documentation set, release script and branch protection.
- [x] ExploitGym evaluated and rejected. It needs a cloud key and a Docker in Docker rig, which conflicts with the local, no key stance.

## Now (next 2 to 4 weeks)

- [ ] **Stabilize the graph canvas browser test** (S): The latest `main` run timed out on `test_canvas_renders_nodes` while 75 other browser tests passed; a flaky check blocks every PR. Ref: CI run `45565074408`.
- [ ] **Make the coverage gate actually block merges** (S): CI showed green while coverage printed 89.98 percent; a gate that does not fail gives false confidence. Refs: `pyproject.toml` and the `coverage` target in `Makefile`.
- [ ] **Triage the 30 open PRs** (M): Every PR from #30 through #81 has been conflicting since 5 November 2026; rebase, close or fold each before starting new work. Refs: open PR list, and merged #28, #72, #42 and #40 for work that may already be covered.
- [ ] **Salvage the small engagement PRs first** (M): #32 session recon, #36 engagement compare, #43 CPE correlate and #45 CVSS rescore add operator value with modest code; rebase them and test against current schemas.
- [ ] **Land the fuzz chain in dependency order** (M): #73 AFL runner, #75 crash bisection, #76 PCAP seeds and #81 coverage import build on the merged corpus store (#72) and should follow the PR triage.
- [ ] **Add schema migrations and a dependency container** (M): `engagements.db` relies on additive table creation and `app_state` uses module singletons; both get harder with every new service. Refs: TD-11 and TD-12 in the dev backlog document.
- [ ] **Refresh stale docs counts and version notes** (S): README shows 1367 tests, CURRENT_STATE shows 1806 and CI reports 1828; docs that disagree with CI slow down new contributors.
- [ ] **Cut the next release once the gate is green** (S): The release guide lists the checks, image tags and one line `docker run` for a version bump; do not tag a red build.

## Next (1 to 3 months)

- [ ] **Ship the remaining fuzz protocol PRs** (L): #66 WebSocket, #67 gRPC, #68 GraphQL, #69 OpenAPI and #70 session fuzz widen protocol coverage; each needs a current rebase, scope checks and a sandbox stand in for CI.
- [ ] **Rebase the cloud and container PRs in small batches** (L): #57 image scan, #59 docker socket guard, #61 Helm rules, #62 Terraform rules, #64 IAM hygiene and #65 S3 policy share scope and ledger patterns; batch them to keep reviews small.
- [ ] **Review the active toolkit PRs before merge** (L): #49 XSS catch, #50 SQLmap flow, #51 Hydra tune, #52 ffuf and wpscan, #53 impacket one click helpers, #54 NTLM relay and #55 pivot tunnel touch live tooling; verify opt in rules and scope ledgers first.
- [ ] **Resolve duplicate implementations** (M): Main already has `bloodhound_ce.py` and `lateral.py`; keep one owner for SharpHound ingest (#47) and tunnel helpers (#55).
- [ ] **Turn the job list into a work queue** (M): `GET /api/jobs` merges job families; cancel and retry plus an attack surface score per host would make the queue actionable. Refs: F-13 and F-14 in the dev backlog document.
- [ ] **Add a wordlist picker and per tool quotas** (M): Wordlists are discovered in `/api/capabilities` but cannot be selected, and `H4K_RATE_LIMIT` only throttles HTTP. Refs: F-11 and TD-16.
- [ ] **Add snapshot import UI and visual regression checks** (M): Snapshot export works but import needs a browser path, and the browser suite has no screenshots; both reduce regression risk. Refs: F-15 and F-18.
- [ ] **Wire dependency scanning into CI** (S): `safety` is installed but unused, while Dependabot covers pip, Docker, actions and the demo npm fixture; add a scheduled audit of h4k itself.
- [ ] **Add a plugin interface** (L): F-17 would let custom tools and report sections live outside the core app, but only after migrations and test stability improve.

## Later

- [ ] **Supply chain depth** (L): Backlog #67 to #71 cover vulnerable dependency to sink paths, VEX, typosquat signals, SLSA provenance, license gates, SBOM diff and OS package audit.
- [ ] **Patch and disclosure workflow** (M): Backlog #71 and #72 cover rotation steps, patch proof, disclosure timeline, CVSS builder and an offline CWE browser.
- [ ] **AI guardrails and evaluation** (M): Backlog #74 to #76 cover patch ranking, test skeletons, false positive judging, natural language queries, secret stripping before sends, a cost badge and fixture based evals.
- [ ] **Purple team and defender handoff** (L): Backlog #77 to #79 cover D3FEND, tabletop, deception, CEF and LEEF export, STIX, MISP, TheHive, risk acceptance and CIS and NIST crosswalks.
- [ ] **Portfolio, audit and evidence** (L): Backlog #80 to #84 cover multiple engagement rollup, role views, immutable logs, backup and restore, retention, evidence hashes and custody export.
- [ ] **Platform hardening** (L): Backlog #85 to #89 cover scoped API keys, OIDC, sandbox profiles, resource caps, remote workers, lab traffic kit, telemetry ingest and binary triage.
- [ ] **Specialist packs** (L): Backlog #90 to #100 cover IoT and OT, AD attacks, BloodHound CE, domain audit, endpoint telemetry, web headers, web inject, web logic, cache checks, fuzz workbench and nightly autopilot.

## Quality and DevOps

- **Tests** (S): Keep unit and API tests offline with the fake MSF client; every new PR needs tests in `tests/` or `tests/e2e/`, and the quarantine list must record a reason and a fix link for any skipped browser test.
- **Coverage** (S): `pyproject.toml` sets a 90 percent gate; CI currently prints 89.98 percent yet passes, so fix the gate before adding large modules.
- **CI** (M): `ci.yml` has `lint-test` and `e2e` as required checks; `qualify.yml` is weekly, on demand and triggered by runtime code PRs as an advisory signal. Pin build time tool downloads.
- **Security scanning** (S): `make lint` runs bandit, shellcheck and hadolint; keep every `# nosec` tied to a rule and rationale, and schedule the already installed `safety` check for h4k dependencies.
- **Containers** (M): `make qualify` builds fresh images and boots the live stack; keep the platform, vulnlab and sidecars on the same compose network, and keep sandbox mode as the offline fallback.
- **Releases** (S): Bump `h4k/api/main.py`, update `RELEASE_NOTES.md` and this roadmap, then run `scripts/release.sh`; never tag while CI is red.

## Known risks

- **The merge gate is unreliable.** One browser test timed out on `main`, and the coverage gate printed a failure while the job stayed green. Both need fixes before a release.
- **The PR queue is rotting.** Thirty conflicting PRs from 5 November 2026 will drift further from `main`, and some duplicate already merged work.
- **Duplicate modules are likely.** SharpHound ingest (#47) overlaps `bloodhound_ce.py`, and tunnel helpers (#55) overlap `lateral.py`; merging both paths would split ownership.
- **The product handles real secrets and real attacks.** Reports keep plaintext credentials, authentication is opt in and h4k often runs as root. Treat exports as secrets and keep the API off shared networks.
- **Some signals are deliberately bounded.** The HTTP fuzzer is signal guided, not coverage guided, SCA needs a committed lockfile, and SAST findings are candidates that an analyst must confirm.
- **Documentation drifts.** README, CURRENT_STATE, the release guide and the Dockerfile disagree on test counts and base image. Refresh them with each release.
- **Large later items stay unscheduled.** The grouped backlog gives direction, but picking too many at once risks another stale PR queue. Ship small verified increments.
