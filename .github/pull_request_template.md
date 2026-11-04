# What

Short paragraph: what changed and why.

# Scope of testing

- [ ] `make lint` green
- [ ] `make test` green (coverage gate held: ___%)
- [ ] `make e2e` green (or N/A — no UI change)
- [ ] Docs updated (`docs/`, `AGENTS.md`, `RELEASE_NOTES.md`, `ROADMAP.md`) if behaviour changed

# Safety checklist (required for aggressive/network-touching changes)

- [ ] Opt-in and off by default
- [ ] Scope enforced in the store, not just the UI
- [ ] No fabricated findings; errors are honest
- [ ] No secrets committed (scan data, creds, logs)
