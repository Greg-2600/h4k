# Security policy

**h4k is an offensive-security tool.** It may only be used against systems
you own or have written permission to test (see
[docs/user/safety.md](docs/user/safety.md)).

## Reporting a vulnerability *in h4k itself*

If you find a bug in h4k that could lead to unintended attacks — a scope
check that can be bypassed, a command-injection in a tool wrapper, a
credential leak — **do not open a public issue**. Use [private vulnerability
reporting](https://github.com/Greg-2600/h4k/security/advisories/new) with:

1. what you did,
2. what you expected (scope enforced, no execution, no leak),
3. what happened instead, including logs.

## Safe harbour for researchers

Testing h4k's own code (in your own checkout, against your own lab) is
encouraged. Do not point a running instance at third-party infrastructure.

## What is and is not protected

The full threat model lives in
[docs/security/threat-model.md](docs/security/threat-model.md). The short
version: aggressive actions are opt-in and scope-enforced, but API
authentication is opt-in (`H4K_API_KEY`), reports contain plaintext
credentials, and the tool executes real attacks when told to. Operate it
like the loaded tool it is.
