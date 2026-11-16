from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_crate(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "name": obj.get("name"),
        "version": obj.get("version"),
        "advisory": obj.get("advisory"),
        "severity": obj.get("severity"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{name}|{version}|{advisory}|{severity}|{yanked}|{iat}|{nonce}".format(**obj)

def admit_crate(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    name = obj.get("name")

    crates = policy.get("crates", {})
    entry = crates.get(name)
    if entry is None:
        reasons.append("crate_unknown")
        entry = {}
    elif obj.get("version") not in entry.get("versions", []):
        reasons.append("version_unknown")

    ranks = policy.get("severity_rank", {})
    sev_rank = ranks.get(obj.get("severity"))
    max_rank = ranks.get(entry.get("max_severity"))
    if sev_rank is None or max_rank is None or sev_rank > max_rank:
        reasons.append("severity_exceeded")

    if entry.get("forbid_yanked") and obj.get("yanked") == 1:
        reasons.append("yanked_forbidden")

    key = keys.get("keys", {}).get(obj.get("kid"))
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        digest = hmac.new(
            bytes.fromhex(key["secret"]),
            _signing_line(obj).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("sig_invalid")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "name": name}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "name": name}
