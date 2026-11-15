from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_assertion(a: dict) -> dict:
    return {"kid": a.get("kid"), "issuer": a.get("issuer"), "audience": a.get("audience"), "recipient": a.get("recipient"), "nonce": a.get("nonce")}

_SIG_FIELDS = ("kid", "issuer", "audience", "recipient", "subject", "not_before", "not_on_or_after", "nonce")

def _signing_input(a: dict) -> bytes:
    return ("v1|" + "|".join(str(a[f]) for f in _SIG_FIELDS)).encode("utf-8")

def _expected_sig(secret_hex: str, a: dict) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), _signing_input(a), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_assertion(a: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    try:
        nb = int(a["not_before"]); nooa = int(a["not_on_or_after"])
        for f in _SIG_FIELDS:
            a[f]
        a["sig"]
    except (KeyError, TypeError, ValueError):
        return {"decision": "deny", "reason_codes": ["malformed"], "subject": a.get("subject")}

    key_entry = (keys.get("keys") or {}).get(a["kid"])
    if key_entry is None:
        reasons.append("unknown_kid")
    elif key_entry.get("status") == "revoked":
        reasons.append("kid_revoked")
    elif not hmac.compare_digest(_expected_sig(key_entry["secret"], a), str(a["sig"])):
        reasons.append("bad_signature")

    if a["issuer"] not in (policy.get("allowed_issuers") or []):
        reasons.append("issuer_not_allowed")
    if a["audience"] not in (policy.get("allowed_audiences") or []):
        reasons.append("audience_not_allowed")
    if a["recipient"] not in (policy.get("allowed_recipients") or []):
        reasons.append("recipient_not_allowed")

    skew = int(policy.get("clock_skew_seconds") or 0)
    if nb > now_unix + skew:
        reasons.append("not_yet_valid")
    if now_unix >= nooa:
        reasons.append("expired")

    if a["nonce"] in (store.get("items") or {}):
        reasons.append("nonce_replayed")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "subject": a.get("subject")}
    store.setdefault("items", {})[a["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "subject": a.get("subject")}
