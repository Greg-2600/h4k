# h4k — Metasploit Lab

School cybersecurity project: a containerized Metasploit Framework lab for
automated security testing against **your own / authorized local lab machines only**.

## Layout

- `Dockerfile` - builds the Metasploit container (Debian 12 + Rapid7 apt repo + nmap)
- `scripts/` - automation scripts run inside the container

## Build & run

```sh
# build
docker build -t h4k h4k

# interactive shell
docker run --rm -it --network host h4k

# run an automation script
docker run --rm --network host -v "$PWD/h4k/scripts:/opt/scripts" h4k \
  bash /opt/scripts/scan.sh TARGET_IP
```

Use `--network host` so the container can reach your local lab hosts directly.

## Legal / ethical (school)

Automation executes exploitation commands. Use **only** against systems you
control or have explicit written authorization to test (e.g. the school lab
range / your own VMs). Do not run against hosts without permission.
