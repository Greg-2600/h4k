"""Loot vault with redaction (Backlog #12).

Verified credentials, captured flags and enumerated shares accumulate
across an engagement — exactly the data that must never leak into a
screenshot, a pasted log or a report. The vault is the single masked
view over all three:

- every secret is masked by default (`reveal=false`),
- masked export (`.json` / `.md`) for handoff and reporting,
- full values only with explicit `reveal=true` on a per-call basis —
  nothing persists unmasked, the store itself is untouched.

Read-only over the engagement and flag stores. SSH key material is out
of scope: no collector banks it, so the vault never fabricates it.
"""

from __future__ import annotations

from typing import Any


def mask_secret(value: str | None, keep: int = 0) -> str:
    """Mask a secret, keeping `keep` trailing chars as a hint."""
    text = str(value or "")
    if not text:
        return ""
    if keep > 0 and len(text) > keep + 4:
        return f"{'•' * 8}{text[-keep:]}"
    return "•" * max(8, min(len(text), 12))


def mask_flag(value: str | None) -> str:
    """Mask a flag keeping only its wrapper shape (e.g. `CTF{…}`)."""
    text = str(value or "")
    if "{" in text and "}" in text:
        return text.split("{", 1)[0] + "{•••}"
    return mask_secret(text)


def vault_summary(
    store: Any, engagement_id: str, reveal: bool = False
) -> dict[str, Any]:
    """Masked loot rollup for one engagement."""
    if not store.get_engagement(engagement_id):
        raise ValueError("unknown engagement")
    credentials: list[dict[str, Any]] = []
    for cred in store.credentials(engagement_id):
        if not cred.get("verified"):
            continue
        hosts = [h.get("host") for h in cred.get("hosts", []) if h.get("host")]
        credentials.append(
            {
                "type": "credential",
                "user": cred.get("user"),
                "password": (
                    cred.get("password")
                    if reveal
                    else mask_secret(str(cred.get("password") or ""), keep=2)
                ),
                "service": cred.get("service"),
                "hosts": sorted(set(hosts)),
                "revealed": bool(reveal),
            }
        )
    flags: list[dict[str, Any]] = []
    try:
        from services.flags import FlagStore

        for flag in FlagStore().list_flags(engagement_id):
            flags.append(
                {
                    "type": "flag",
                    "value": (
                        flag.get("value")
                        if reveal
                        else mask_flag(str(flag.get("value") or ""))
                    ),
                    "host": flag.get("host"),
                    "revealed": bool(reveal),
                }
            )
    except Exception:
        pass
    shares: list[dict[str, Any]] = []
    list_shares = getattr(store, "shares", None)
    if callable(list_shares):
        try:
            for share in list_shares(engagement_id):
                shares.append(
                    {
                        "type": "share",
                        "host": share.get("host"),
                        "share": share.get("share"),
                        "access": share.get("access"),
                    }
                )
        except Exception:
            pass
    items = credentials + flags + shares
    return {
        "engagement_id": engagement_id,
        "revealed": bool(reveal),
        "counts": {
            "credentials": len(credentials),
            "flags": len(flags),
            "shares": len(shares),
        },
        "items": items,
        "count": len(items),
    }


def vault_markdown(store: Any, engagement_id: str, reveal: bool = False) -> str:
    """Masked markdown export of the vault (report/handoff friendly)."""
    eng = store.get_engagement(engagement_id)
    if not eng:
        raise ValueError("unknown engagement")
    summary = vault_summary(store, engagement_id, reveal=reveal)
    lines = [
        f"# Loot vault — {eng.get('name') or engagement_id}",
        "",
        (
            "_Secrets masked by default; re-export with reveal to unmask._"
            if not reveal
            else "_UNMASKED export — handle as sensitive._"
        ),
        "",
        f"_{summary['count']} item(s): "
        f"{summary['counts']['credentials']} credential(s), "
        f"{summary['counts']['flags']} flag(s), "
        f"{summary['counts']['shares']} share(s)._",
        "",
    ]
    for item in summary["items"]:
        if item["type"] == "credential":
            lines.append(
                f"- cred `{item['user']}` ({item['service'] or 'any'}) "
                f"on {', '.join(item['hosts']) or '?'}: `{item['password']}`"
            )
        elif item["type"] == "flag":
            lines.append(f"- flag `{item['value']}` on {item['host'] or '?'}")
        else:
            lines.append(
                f"- share `\\\\{item['host']}\\{item['share']}` ({item['access'] or '?'})"
            )
    lines.append("")
    return "\n".join(lines)
