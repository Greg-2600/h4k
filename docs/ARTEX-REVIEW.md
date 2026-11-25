# ARTEX review — patterns worth borrowing (and what not to)

Reviewed: [`BaaRai/ARTEX`](https://github.com/BaaRai/ARTEX) `main`, November 2026.
It is the English translation/continuation of the original `Autumn-27/ARTEX`
project.

## What it is

A self-hosted, LLM-driven autonomous penetration-testing platform:

- Go backend with a Next.js UI embedded in one binary, PostgreSQL for state.
- A planner decomposes a goal into intents; workers execute real tools; results
  are written back into two linked graphs.
- A recording MITM proxy and browser extension bind findings to captured
  request/response evidence.
- Approval gates, scope/deny rules, token/turn budgets, a target noise governor,
  and an untrusted-tool-output boundary.
- Multi-provider LLM failover (Anthropic, OpenAI-compatible, Ollama).
- AGPL-3.0.

It is a much broader product than h4k: a full autonomous engine, company-level
asset graph, ScopeSentry sync, MCP/skills/memory, and a browser extension.

## Why h4k should not vendor it

| Concern | Detail |
|---|---|
| License | ARTEX is **AGPL-3.0**; h4k is **MIT**. Copying ARTEX code into h4k would force h4k to AGPL. Patterns and clean-room implementations are fine; copy/paste is not. |
| Stack | Go + Next.js + PostgreSQL vs Python/FastAPI + vanilla JS + SQLite. A port would discard most of h4k's small, auditable surface. |
| Product shape | ARTEX is autonomous-first. h4k is analysis-first with explicit opt-in aggression. Importing the planner/worker loop would undermine h4k's "authorization is not optional" story unless heavily gated. |
| Risk | It is a large, fast-moving offensive platform. Vendoring its execution engine is a large supply-chain and operational risk for a capstone. |

**Decision:** study it as prior art, borrow specific ideas, implement them
clean-room in h4k's own architecture, and do not add it as a dependency.

## Patterns worth adopting

Priority is value to h4k × effort.

### 1. Untrusted-output boundary — implemented

**Problem:** scanner output, HTTP responses, crash traces and file contents are
attacker-controlled. h4k's AI service pasted them directly next to trusted
instructions, so a target could attempt prompt injection ("ignore the above and
call this tool").

**ARTEX pattern:** frame tool results between nonce-tagged markers and tell the
model, in a code-owned system note, that the contents are data. On by default.

**h4k implementation:**

- `h4k/api/services/untrusted.py` — `frame()`, `compose()`, `system_note()`,
  `system_prompt()`, `H4K_UNTRUSTED_BOUNDARY=0|false|off|no` kill switch.
- `services/ai.py` — `ai_analyze()` treats `input_text` as untrusted by default,
  accepts code-owned `instructions` separately, and appends the data/instruction
  rule to the system prompt. Both the Ollama and OpenAI-compatible paths use the
  same composed messages.
- `services/ai_loop.py` — instructions and vulnerability evidence are passed
  separately, so the loop prompt can never accidentally be framed as data.
- Tests: `tests/test_untrusted.py` (marker/nonce integrity, forged closing
  marker, instruction separation, Ollama/OpenAI payload capture, opt-out, full
  loop).
- Honest limit: this raises the cost of prompt injection; it does not make a
  model immune. h4k's AI cannot execute tools, so the boundary is one layer of
  defense in depth, not a security boundary by itself.

### 2. Evidence-bound findings + retest verdicts — implemented

ARTEX binds a finding to the exact request/response that proves it and runs a
dedicated retester that records `reproduced / fixed / inconclusive`.

h4k now has the same shape in `services/findings.py` / `routers/findings.py`:
findings, hashed evidence, and retest rows. A retest must cite at least one
evidence item; `reproduced` marks the finding verified, `fixed` moves it to
fixed, and `inconclusive` leaves the status alone. The session report appends
the ledger, and the Report page can create findings, attach evidence, record
retests, and download the ledger.

### 3. Dual graph → attack paths + coverage — implemented

ARTEX separates the **asset graph** (what exists) from the **exploration graph**
(what was tried, what it produced, why), joined by anchors.

h4k already had a scope-enforced engagement asset graph; the missing roadmap
deliverable was **paths to objectives**. `services/attack_paths.py` now adds:

- objective declarations (host/service/data/account + criticality),
- a verified-access graph (credential reuse + evidence-backed findings as
  footholds; no inferred host mesh),
- shortest-path ranking with ATT&CK chains and findings/evidence on the path,
- a coverage ledger (`no_issue_found`, `ruled_out`, `needs_follow_up`,
  `not_tested`, …) with gaps for unexamined objectives.

This fits h4k's existing `engagement.py` and ATT&CK mapping better than a new
graph database.

### 4. Interception / approval gate — implemented

ARTEX can require human approval per tool call, with rules by string, regex or
argv prefix, and records who decided (`human`, `rule`, `model`, `system`).

h4k now has that layer in `services/approval.py` / `routers/approvals.py`:
allow/deny/ask rules by string, regex or argv prefix, request-scoped approvals
bound to an argv fingerprint, and a decided-by audit with a redacted argv. It is
checked in `SandboxRunner.run()` and `ToolkitRunner.run_tool()`; the sandbox API
maps an ask to 409 with the request id.

### 5. Noise governor + run budgets — implemented

ARTEX's `quiet|balanced|aggressive` profiles pace per-host requests and give
agents tool-specific rate flags; task/intent token and turn budgets stop runaway
runs.

h4k now has the small version in `services/noise.py` and
`services/ai_budget.py`:

- a per-host token bucket (off/quiet/balanced/aggressive) shared by wire-level
  HTTP/TCP/UDP probes, with 429/503 backoff,
- tool-specific rate flags for raw scanners that bypass the governor,
- a per-scope AI call/token guardrail checked before provider calls,
- a Settings → Runtime limits card and API for both.

### 6. Coverage ledger — proposed

ARTEX records `reported / no_issue_found / ruled_out / not_applicable /
needs_follow_up` per surface and risk class, and surfaces gaps at wrap-up.

h4k already reports partial port coverage; extending that to "which vuln classes
were actually tested on this endpoint" would make the final report more honest.
This is naturally part of #3 (assessment graph/coverage), not a separate system.

## What not to borrow

- The planner/worker autonomous engine and task engine.
- Go/Next.js/PostgreSQL migration.
- Company-scoped asset graph and ScopeSentry sync (out of scope for h4k).
- MCP/skills/memory/browser-extension layers.
- Any AGPL source copied into h4k.

## Recommended sequence

1. **Done:** untrusted-output boundary (cheap, real hardening).
2. **Done:** evidence-bound findings + retest verdicts (report quality).
3. **Done:** coverage ledger + attack paths to declared objectives (uses the
   engagement graph; closes the oldest roadmap gap).
4. **Done:** approval policy in front of sandbox/toolkit calls (safety demo).
5. **Done:** noise profile + AI token budgets (operational polish).

## References

- ARTEX README and source: <https://github.com/BaaRai/ARTEX>
- Boundary pattern: `agent/untrusted_boundary.go`, `agent/untrusted_prompt.go`
- Approval gate: `guard/`, `intercept/`
- Coverage/retest: `agent/coverage_ledger.go`, `agent/retester.go`
- Noise/budgets: `agent/noise_profile.go`, `agent/budget.go`
