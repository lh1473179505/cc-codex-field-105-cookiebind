from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_keyset(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "kid_new": obj.get("kid_new"),
        "kid_old": obj.get("kid_old"),
        "overlap": obj.get("overlap"),
        "alg": obj.get("alg"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{issuer}|{kid_new}|{kid_old}|{overlap}|{alg}|{iat}|{nonce}".format(**obj)

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def admit_keyset(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    kid_new = obj.get("kid_new") if isinstance(obj, dict) else None

    required = ("issuer", "kid_new", "kid_old", "overlap", "alg", "nonce", "iat", "kid", "sig")
    if not isinstance(obj, dict) or any(k not in obj for k in required):
        return {"decision": "deny", "reason_codes": ["malformed"], "kid_new": kid_new}
    if not isinstance(obj["overlap"], int) or isinstance(obj["overlap"], bool):
        return {"decision": "deny", "reason_codes": ["malformed"], "kid_new": kid_new}
    if not isinstance(obj["iat"], int) or isinstance(obj["iat"], bool):
        return {"decision": "deny", "reason_codes": ["malformed"], "kid_new": kid_new}
    for k in ("issuer", "kid_new", "kid_old", "alg", "nonce", "kid", "sig"):
        if not isinstance(obj[k], str):
            return {"decision": "deny", "reason_codes": ["malformed"], "kid_new": kid_new}

    if obj["issuer"] not in policy.get("allowed_issuers", []):
        reasons.append("issuer_not_allowed")
    if obj["alg"] not in policy.get("algs", []):
        reasons.append("alg_not_allowed")
    if policy.get("forbid_same_kid") and obj["kid_new"] == obj["kid_old"]:
        reasons.append("same_kid")
    if not (policy["overlap_min"] <= obj["overlap"] <= policy["overlap_max"]):
        reasons.append("overlap_out_of_range")

    key_entry = keys.get("keys", {}).get(obj["kid"])
    if key_entry is None:
        reasons.append("unknown_kid")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        try:
            secret = bytes.fromhex(key_entry["secret"])
            expected = hmac.new(secret, _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
            actual = _b64url_decode(obj["sig"])
        except (ValueError, KeyError):
            reasons.append("bad_signature")
        else:
            if not hmac.compare_digest(expected, actual):
                reasons.append("bad_signature")

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if obj["iat"] > now_unix + skew:
        reasons.append("iat_in_future")
    elif now_unix - obj["iat"] > max_age:
        reasons.append("iat_expired")

    items = store.get("items", {})
    if obj["nonce"] in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "kid_new": kid_new}
    items[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "kid_new": kid_new}
