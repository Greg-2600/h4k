# vulnlab — intentionally-vulnerable fuzzing target + modern vuln-devel toolchain

A deliberately-buggy HTTP server, in its **own standalone container**, built to
demonstrate real **0-day-discovery methodology** with h4k — using the same
tools professional security researchers use:

| approach | tool | how | result |
|---|---|---|---|
| **Coverage-guided fuzzing** | **libFuzzer + ASan** (`parse_fuzzer`) | follows the parser's control flow | finds the exact overflow in ~seconds |
| **Coverage-guided fuzzing** | **AFL++** (needs `afl-clang-fast`) | same, alternative engine | same |
| Black-box HTTP mutation | h4k `/api/fuzz` | blind mutation over the wire | catches the crash crudely |

> **WARNING — UNSAFE ON PURPOSE.** This image contains real memory-safety bugs
> and is compiled **without** stack canaries. It is a teaching target only, runs
> in its own sandboxed container against itself, and must never be exposed
> beyond your machine. It is not a template for real code.

## The bugs (so fuzzing finds a *real* crash)

`vulnlab_parse()` in `vulnlab.c` is called by **both** the network server and
the fuzz harnesses — so what coverage guidance exercises is the same code the
wire sees.

- **B1 — stack buffer overflow**: attacker bytes copied into a 256-byte stack
  buffer with no bounds check; one byte is written past the end. → ASan
  `stack-buffer-overflow`.
- **B2 — format string**: attacker bytes used directly as a `printf` format;
  `%n` aborts under ASan. → ASan abort.

## Build & run (the important parts)

```sh
# the live, supervisord-restarted HTTP server (crashes -> restarts)
docker build -t vulnlab vulnlab/
docker run --rm --name vulnlab -p 127.0.0.1:8080:8080 vulnlab
curl http://127.0.0.1:8080/          # -> vulnlab v1.0
```

**Coverage-guided, the RIGHT way** (inside the container you built):

```sh
docker run --rm vulnlab \
  sh -c 'mkdir -p /opt/corpus && printf AAAA > /opt/corpus/seed && \
         ASAN_OPTIONS=detect_leaks=0 \
         /usr/local/bin/parse_fuzzer -runs=50000 -max_len=1024 /opt/corpus/'
```

libFuzzer + ASan will report something like:

```
==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1 at ... in vulnlab_parse /opt/vulnlab.c:48
SUMMARY: AddressSanitizer: stack-buffer-overflow /opt/vulnlab.c:48
```

That **is** the new-vuln discovery step, done properly. It then drops a
minimized repro in `crash-*` for triage.

**The h4k end-to-end black-box loop** (service-crash discovery, from h4k):

1. Keep vulnlab running (supervisor auto-restarts it on crash).
2. In h4k's operation pane: target `127.0.0.1`, fuzz port `8080`, confirm (lab).
3. Watch it flag the overflow → vulnlab logs *"terminated by SIGSEGV"* and
   supervisor brings it back.

## The modern vuln-devel workflow (what to teach)

1. **Build with sanitizers** (ASan + UBSan) — make silent memory bugs loud.
2. **Fuzz coverage-guided** (libFuzzer/AFL++), not blind — it finds real bugs in
   seconds because it follows program control flow.
3. **Capture the crash + minimize the repro** — libFuzzer writes a `crash-*`
   file; `-minimize_crash=1` shrinks it to the smallest triggering input.
4. **Prove root cause** — the ASan stack trace names the exact function/line.
5. **Disclose responsibly** — report to the vendor, wait for their fix/response,
   then publish. Never dump a 0-day publicly before a patch exists.

This is the whole point: **new bugs are found by fuzzing a service you control
yourself, letting sanitizers + coverage guidance pinpoint the flaw, and turning
the minimal repro into a responsible disclosure.** — not by running a scanner
against someone else's box.
