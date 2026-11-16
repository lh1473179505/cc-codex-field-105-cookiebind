from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_req(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "bucket": obj.get("bucket"),
        "key": obj.get("key"),
        "method": obj.get("method"),
        "expires": obj.get("expires"),
        "nonce": obj.get("nonce"),
    }

def _sign_line(obj: dict) -> str:
    return "v1|{kid}|{bucket}|{key}|{method}|{expires}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        bucket=obj.get("bucket"),
        key=obj.get("key"),
        method=obj.get("method"),
        expires=obj.get("expires"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def admit_req(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    key = obj.get("key")
    bucket = obj.get("bucket")
    method = obj.get("method")
    expires = obj.get("expires")
    iat = obj.get("iat")
    nonce = obj.get("nonce")
    kid = obj.get("kid")

    if not isinstance(key, str) or not isinstance(bucket, str) or not isinstance(method, str):
        reasons.append("malformed_request")
    if not isinstance(expires, int) or isinstance(expires, bool) or expires <= 0:
        reasons.append("bad_expires")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("bad_iat")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("bad_nonce")
    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "key": key}

    buckets = policy.get("buckets", {})
    bp = buckets.get(bucket)
    if bp is None:
        reasons.append("bucket_not_allowed")
    else:
        if not any(key.startswith(p) for p in bp.get("key_prefixes", [])):
            reasons.append("prefix_not_allowed")
        for sub in bp.get("deny_key_substrings", []):
            if sub and sub in key:
                reasons.append("key_denied")
                break
        if method not in bp.get("methods", []):
            reasons.append("method_not_allowed")
        if expires > bp.get("expires_max", 0):
            reasons.append("expires_too_large")

    entry = keys.get("keys", {}).get(kid)
    if entry is None:
        reasons.append("unknown_kid")
    elif entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        expected = _expected_sig(entry["secret"], _sign_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_sig")

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if iat - now_unix > skew:
        reasons.append("iat_in_future")
    elif now_unix - iat > max_age:
        reasons.append("iat_too_old")

    if nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "key": key}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "key": key}
