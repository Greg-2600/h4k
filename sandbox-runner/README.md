# h4k sandbox runner

A tiny HTTP executor for aggressive tooling, isolated from the API container.
The API already enforces resource limits locally (`services/sandbox.py`); this
sidecar is the stronger boundary: the process tree runs as an unprivileged user
inside its own container, with CPU/memory/process/file-size rlimits, a scrubbed
environment, a throw-away working directory, and a tool allowlist per profile.

## Run

```sh
# from the repo root
docker compose -f h4k/docker-compose.yml --profile sandbox up -d sandbox-runner
# then point the API at it
docker run ... -e H4K_SANDBOX_URL=http://127.0.0.1:9099 \
               -e H4K_SANDBOX_TOKEN=change-me h4k
```

The token is required: without `H4K_SANDBOX_TOKEN` the runner refuses every
`/run` request (it still answers `/health`).

## API

```sh
curl -s localhost:9099/health
curl -s localhost:9099/run \
  -H "X-Sandbox-Token: change-me" -H "Content-Type: application/json" \
  -d '{"profile":"recon","argv":["nmap","-sT","-p22","127.0.0.1"],"timeout_s":30}'
```

Profiles mirror `h4k/api/services/sandbox.py`: `recon`, `web`, `creds`, `ad`,
`lab`, `full`. The request can only *narrow* the profile's runtime; it cannot
raise the limits.

## Verified

Built as `h4k-sandbox-runner:latest` and exercised over HTTP: `/health` lists
the profiles, an allowlisted `nmap --version` runs, and a disallowed `bash`
command is rejected.

## Safety

- Read-only root filesystem is supported (`--read-only --tmpfs /tmp`) because all
  work happens in a temporary directory.
- `RLIMIT_NPROC` is safe here because the container runs a dedicated user.
- No shell is ever invoked; `argv` is executed directly.
- Output is truncated at 512 KiB per stream.
