# h4k telemetry agent

Tails JSON-lines endpoint telemetry and ships it to h4k. No dependencies, no
privileged access: it only reads the files you mount.

## What to feed it

Any JSON-lines source works — the normalizer recognizes Sysmon, Windows Security
events, auditd JSON, osquery and Zeek-shaped records. Examples:

```jsonl
{"EventID":"1","Computer":"ws01","Channel":"Microsoft-Windows-Sysmon/Operational","Message":"powershell.exe -EncodedCommand ..."}
{"event_id":"4769","host":"dc01","message":"Kerberos service ticket, encryption type 0x17"}
{"ts":"2026-01-01T00:00:00Z","host":"plc01","source":"ot","message":"modbus fc=16 write"}
```

## Run

```sh
docker compose -f h4k/docker-compose.yml --profile telemetry up -d telemetry-agent
# or directly
docker run --rm --network host \
  -e H4K_URL=http://127.0.0.1:3137 \
  -e H4K_AGENT_FILES=/var/log/h4k/events.jsonl \
  -e H4K_AGENT_SOURCE=sysmon \
  -v /var/log/h4k:/var/log/h4k:ro \
  h4k-telemetry-agent
```

For a quick demo without a log source:

```sh
docker run --rm --network host -e H4K_AGENT_SYNTHETIC=1 h4k-telemetry-agent
```

## Verified

Built as `h4k-telemetry-agent:latest`; a one-shot synthetic run against a live
h4k API produced an accepted event and an ATT&CK detection.

## Config

| Env | Default | Meaning |
|---|---|---|
| `H4K_URL` | `http://127.0.0.1:3137` | h4k base URL |
| `H4K_API_KEY` | empty | API key when `H4K_AUTH_ENABLED=1` |
| `H4K_AGENT_FILES` | empty | comma-separated log files |
| `H4K_AGENT_SOURCE` | `agent` | fallback source label |
| `H4K_AGENT_FROM_START` | `0` | read existing lines instead of tailing from EOF |
| `H4K_AGENT_SYNTHETIC` | `0` | emit a demo event every interval |
| `H4K_AGENT_INTERVAL` | `2` | seconds between flushes |
| `H4K_AGENT_ONCE` | `0` | send the backlog and exit |

Events are deduplicated server-side by `event_uid` (or a hash of
timestamp/source/host/event/message), so restarting the agent does not double
count.
