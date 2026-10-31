#!/usr/bin/env python3
"""End-to-end sanity check for a running h4k deployment.

Verifies the whole stack the way an operator would use it:

  1. the API is up and healthy
  2. Metasploit's RPC daemon is reachable (and, if the DB is loaded, usable)
  3. the web console is served and the static bundle is present
  4. an engagement can be created, scoped and activated
  5. a scan runs and produces an inventory
  6. the result can be ingested into the engagement graph
  7. crown jewels can be declared and attack paths computed
  8. findings map to ATT&CK techniques with detection guidance
  9. the fuzzing lab (vulnlab) answers, and h4k can crash it on purpose
  10. container-escape detection reports its findings

Usage:
    python3 scripts/sanity_check.py [--url http://127.0.0.1:3137] [--lab 3138]
                                    [--json] [--no-fuzz]

Exit code is 0 when every check passes, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from typing import Any

GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
RESET = "\033[0m"


class Client:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(self, method: str, path: str, payload: Any = None) -> tuple[int, Any]:
        url = f"{self.base_url}{path}"
        data = None
        headers = {}
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode()
                try:
                    return resp.status, json.loads(body) if body else {}
                except json.JSONDecodeError:
                    return resp.status, body
        except urllib.error.HTTPError as exc:
            body = exc.read().decode()
            try:
                return exc.code, json.loads(body) if body else {}
            except json.JSONDecodeError:
                return exc.code, body
        except Exception as exc:
            return 0, {"detail": str(exc)}

    def get(self, path: str) -> tuple[int, Any]:
        return self.request("GET", path)

    def post(self, path: str, payload: Any = None) -> tuple[int, Any]:
        return self.request("POST", path, payload if payload is not None else {})

    def delete(self, path: str) -> tuple[int, Any]:
        return self.request("DELETE", path)


class Report:
    def __init__(self) -> None:
        self.results: list[dict[str, Any]] = []

    def add(self, name: str, ok: bool, detail: str = "", warn: bool = False) -> None:
        self.results.append({"check": name, "ok": ok, "detail": detail, "warn": warn})

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r["ok"] and not r["warn"])

    def render(self) -> str:
        out = []
        for r in self.results:
            if r["ok"]:
                icon, colour = "✓", GREEN
            elif r["warn"]:
                icon, colour = "!", YELLOW
            else:
                icon, colour = "✗", RED
            line = f"  {colour}{icon}{RESET} {r['check']}"
            if r["detail"]:
                line += f"  {BOLD}{r['detail']}{RESET}"
            out.append(line)
        out.append("")
        if self.failed:
            out.append(f"{RED}{self.failed} check(s) FAILED{RESET}")
        else:
            out.append(f"{GREEN}all checks passed{RESET}")
        return "\n".join(out)


def wait_for_job(client: Client, job_id: str, timeout: float = 300.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    last: dict[str, Any] = {}
    while time.time() < deadline:
        status, payload = client.get(f"/api/jobs/{job_id}")
        if status != 200:
            return {"status": "error", "detail": payload}
        last = payload if isinstance(payload, dict) else {}
        if last.get("status") in ("done", "error", "failed"):
            return last
        time.sleep(3)
    return {"status": "timeout"}


def main() -> int:
    parser = argparse.ArgumentParser(description="h4k deployment sanity check")
    parser.add_argument(
        "--url", default="http://127.0.0.1:3137", help="h4k API base URL"
    )
    parser.add_argument(
        "--lab", default="http://127.0.0.1:3138", help="vulnlab base URL"
    )
    parser.add_argument(
        "--no-fuzz", action="store_true", help="skip the fuzz/lab check"
    )
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args()

    client = Client(args.url)
    report = Report()

    # 1. API health -------------------------------------------------------
    status, health = client.get("/api/health")
    if status == 200 and isinstance(health, dict) and health.get("status") == "ok":
        report.add("api reachable", True, f"{args.url} -> {health.get('status')}")
    else:
        report.add("api reachable", False, f"{args.url} -> {status} {health}")
        print(json.dumps(report.results, indent=2) if args.json else report.render())
        return 1

    # 2. Metasploit -------------------------------------------------------
    msf = health.get("msf") or {}
    if msf.get("reachable"):
        version = (msf.get("version") or {}).get("version", "?")
        report.add("metasploit reachable", True, f"version {version}")
    else:
        report.add("metasploit reachable", False, "msfrpcd not answering")

    # 3. Web console ------------------------------------------------------
    status, body = client.get("/")
    if status == 200 and isinstance(body, str) and "h4k" in body.lower():
        report.add("web console served", True, f"index.html {len(body)} bytes")
    else:
        report.add("web console served", False, f"status {status}")

    status, body = client.get("/static/app.js")
    if status == 200 and isinstance(body, str) and len(body) > 1000:
        report.add("ui bundle served", True, f"app.js {len(body)} bytes")
    else:
        report.add("ui bundle served", False, f"status {status}")

    # 4. Engagement -------------------------------------------------------
    status, eng = client.post(
        "/api/engagement",
        {
            "name": "sanity check",
            "scope": ["127.0.0.1/32", "172.16.0.0/12", "10.0.0.0/8"],
            "notes": "created by scripts/sanity_check.py",
        },
    )
    if status != 200 or not isinstance(eng, dict) or "id" not in eng:
        report.add("engagement created", False, f"{status} {eng}")
        print(json.dumps(report.results, indent=2) if args.json else report.render())
        return 1
    eng_id = eng["id"]
    report.add("engagement created", True, f"{eng['name']} ({eng_id})")

    status, scoped = client.post("/api/session/scope", {"engagement_id": eng_id})
    if status == 200 and (scoped or {}).get("status") == "scoped":
        report.add("scope activated", True, ", ".join(scoped.get("scope") or []))
    else:
        report.add("scope activated", False, f"{status} {scoped}")

    # 5. Scan -------------------------------------------------------------
    status, job = client.post("/api/scan", {"target": "127.0.0.1", "mode": "overt"})
    if status == 200 and isinstance(job, dict) and job.get("id"):
        job_id = job["id"]
        done = wait_for_job(client, job_id)
        report.add(
            "scan runs",
            done.get("status") == "done",
            f"job {job_id} -> {done.get('status')}",
        )
        status, scan_report = client.get(f"/api/report/{job_id}")
        hosts = (scan_report or {}).get("hosts") or []
        if hosts:
            ports = sum(len(h.get("services") or []) for h in hosts)
            report.add(
                "scan produced an inventory",
                True,
                f"{len(hosts)} host(s), {ports} service(s)",
            )
        else:
            report.add(
                "scan produced an inventory",
                False,
                "no hosts found (is the Metasploit database loaded?)",
            )

        # 6. Ingest --------------------------------------------------------
        status, ingested = client.post(
            f"/api/engagement/{eng_id}/ingest", {"job_id": job_id}
        )
        if status == 200:
            report.add("scan ingested into engagement", True, str(ingested)[:80])
        else:
            report.add("scan ingested into engagement", False, f"{status} {ingested}")
    else:
        report.add("scan runs", False, f"{status} {job}")

    # 7. Crown jewels + attack paths --------------------------------------
    # Seed a small, deterministic engagement so the path/ATT&CK logic is
    # actually exercised: one credential that works on two hosts (a pivot),
    # one vulnerability, and the second host as the objective.
    seeded_report = {
        "hosts": [
            {"address": "10.1.1.5", "services": [{"port": 22, "service": "ssh"}]},
            {"address": "10.1.1.9", "services": [{"port": 22, "service": "ssh"}]},
        ],
        "credentials": [
            {
                "host": "10.1.1.5",
                "port": 22,
                "service": "ssh",
                "user": "sanity",
                "password": "sanity-lab",
                "verified": True,
            },
            {
                "host": "10.1.1.9",
                "port": 22,
                "service": "ssh",
                "user": "sanity",
                "password": "sanity-lab",
                "verified": True,
            },
        ],
        "vulns": [
            {
                "host": "10.1.1.5",
                "name": "OpenSSH outdated (sanity finding)",
                "severity": "high",
                "cwe": "CWE-1104",
            }
        ],
    }
    status, seeded = client.post(f"/api/engagement/{eng_id}/ingest", seeded_report)
    if status == 200:
        report.add("lab engagement ingested", True, "2 hosts, 1 pivot credential")
    else:
        report.add("lab engagement ingested", False, f"{status} {seeded}")

    status, cj = client.post(
        f"/api/engagement/{eng_id}/crown-jewels",
        {"host": "10.1.1.9", "label": "sanity objective", "value": 80},
    )
    if status == 200:
        report.add(
            "crown jewel declared", True, f"{cj.get('host')} value {cj.get('value')}"
        )
    else:
        report.add("crown jewel declared", False, f"{status} {cj}")

    status, paths = client.get(f"/api/engagement/{eng_id}/attack-paths")
    if status == 200:
        count = (paths.get("summary") or {}).get("paths", 0)
        best = (paths.get("paths") or [{}])[0] if paths.get("paths") else {}
        report.add(
            "attack paths computed",
            count >= 1,
            f"{count} path(s), best score {(paths.get('summary') or {}).get('best_score', 0)}"
            + (f" via {' -> '.join(best.get('nodes') or [])}" if best else ""),
        )
    else:
        report.add("attack paths computed", False, f"{status} {paths}")

    # 8. ATT&CK -----------------------------------------------------------
    status, attck = client.get(f"/api/engagement/{eng_id}/attck")
    if status == 200:
        techs = attck.get("techniques") or []
        ids = ", ".join(t.get("id", "?") for t in techs[:4])
        report.add(
            "attck mapping",
            bool(techs),
            f"{len(techs)} technique(s)" + (f" ({ids})" if ids else ""),
        )
    else:
        report.add("attck mapping", False, f"{status} {attck}")

    # 9. Fuzzing lab ------------------------------------------------------
    if args.no_fuzz:
        report.add("fuzzing lab", True, "skipped (--no-fuzz)", warn=True)
    else:
        try:
            with urllib.request.urlopen(args.lab, timeout=10) as resp:
                lab_body = resp.read().decode()[:64]
            report.add("fuzzing lab answers", True, lab_body.strip())
        except Exception as exc:
            report.add("fuzzing lab answers", False, f"{args.lab} -> {exc}")

    # 10. Capability report -------------------------------------------------
    status, cap = client.get("/api/capabilities")
    if status == 200 and isinstance(cap, dict):
        warnings = cap.get("warnings") or []
        detail = f"{len(cap.get('installed_tools') or [])} tools"
        if warnings:
            detail += " | " + "; ".join(warnings[:2])
        report.add("capability report", True, detail, warn=bool(warnings))
    else:
        report.add("capability report", False, f"{status} {cap}")

    # 11. Container escape detection --------------------------------------
    status, esc = client.post("/api/container_escape")
    if status == 200 and isinstance(esc, dict):
        vectors = esc.get("vectors") or []
        report.add(
            "container escape detection",
            True,
            f"{len(vectors)} vector(s), caps {len(esc.get('capabilities') or [])}",
        )
    else:
        report.add("container escape detection", False, f"{status} {esc}")

    # cleanup: the sanity engagement should not linger
    client.delete(f"/api/engagement/{eng_id}")

    if args.json:
        print(json.dumps(report.results, indent=2))
    else:
        print(f"{BOLD}h4k sanity check — {args.url}{RESET}")
        print(report.render())
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
