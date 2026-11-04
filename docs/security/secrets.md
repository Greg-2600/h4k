# Secrets handling

h4k *finds* credentials by design. Handling them safely is the operator's
responsibility. This page lists where secrets live, how they are protected,
and what to do with them.

---

## Where secrets live

| Location | Contents | Protection |
|---|---|---|
| `engagements.db` (`cred_access`, `credentials`, `attempts`) | Verified credentials and every login attempted | File mode `0600`; inside `H4K_DATA_DIR` |
| `neighbors.db` (`found_creds`) | Credentials found during the current session | Same directory |
| Session reports (`/api/session/report`, `/api/export/{id}`) | Hosts, services, **credentials**, vulns | **Plaintext — treat as a secret** |
| `docker logs h4k` | Action log; may include banners and findings | Anyone with log access can read it |
| AI requests | If AI triage is enabled, findings may be sent to a model endpoint | Depends on your provider |

## What is *not* protected by default

* **Authentication is opt-in.** Set `H4K_API_KEY` and every request must
  carry `X-API-Key: <key>` (health/docs stay open). Without it, anyone who
  can reach the port can read the credential store — bind to `127.0.0.1`
  and do not expose it.
* **Exports are not redacted.** A markdown report contains the passwords you
  found. Redact before sharing.
* **`attempts` records failed logins too** — usernames are secrets as well.

## Rules of thumb

1. **Never commit** `h4k/data/*.db`, exports, or `docker logs` containing
   findings. `.gitignore` covers the data directory; check before pushing.
2. **Never paste** a report into a public issue, a chat, or a slide deck
   without redacting credentials and internal hostnames.
3. **Treat the volume like a password manager.** `docker volume rm h4k_data`
   when the engagement closes and the credentials are no longer needed.
4. **Use sandbox mode for demos.** `H4K_SANDBOX=1` has no real credentials
   and no network access — the only safe mode for a classroom screen.
5. **Rotate anything you demoed.** If you ran a real password attack against
   a real host, the accounts may be locked or the passwords may now be in a
   screenshot.

## Redacting a report

```sh
# quick pass over a markdown export
sed -E 's/(login: [^ ]+ +password: )[^ ]+/\1<redacted>/g' report.md > report.safe.md
```

Better: strip the credential sections entirely before sharing:

```sh
curl -s http://127.0.0.1:3137/api/session/report?fmt=md \
  | awk '/## Credentials verified/{skip=1} /^## /{skip=0} !skip'
```

## Third-party model providers

If you enable AI triage:

* `H4K_AI_URL` may point at a local relay (keyless) or a hosted provider.
* **Hosted providers see your findings.** Only send sanitized material, or
  use the local relay.
* API keys come from the environment (`H4K_AI_KEY`); h4k never writes them to
  disk or logs them.

## If a credential leaks

1. Rotate the credential at the target.
2. Delete the engagement (and therefore its credential rows):
   ```sh
   curl -X DELETE http://127.0.0.1:3137/api/engagement/$ID
   ```
3. Purge the session store if needed:
   ```sh
   docker volume rm h4k_data
   ```
4. Check your shell history, CI logs and chat transcripts for copies.
5. If it reached a git repository, treat it as compromised — rewriting
   history does not un-publish it.
