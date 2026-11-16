from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_wrap(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "key_id": obj.get("key_id"),
        "wrapping_key": obj.get("wrapping_key"),
        "algorithm": obj.get("algorithm"),
        "usage": obj.get("usage"),
        "encoding": obj.get("encoding"),
        "key_bytes": obj.get("key_bytes"),
        "nonce": obj.get("nonce"),
    }

def _sig_line(obj: dict) -> str:
    usage = obj.get("usage")
    usage_str = ",".join(usage) if isinstance(usage, list) else str(usage)
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("profile")),
        str(obj.get("key_id")),
        str(obj.get("wrapping_key")),
        str(obj.get("algorithm")),
        usage_str,
        str(obj.get("encoding")),
        str(obj.get("key_bytes")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _valid_key_id(key_id: Any) -> bool:
    if not isinstance(key_id, str) or not key_id:
        return False
    if key_id.startswith("/") or key_id.endswith("/"):
        return False
    parts = key_id.split("/")
    return all(p not in ("", ".", "..") for p in parts)

def admit_wrap(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    key_id = obj.get("key_id")

    kid = obj.get("kid")
    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("unknown_kid")
        secret = None
    else:
        if key_entry.get("status") != "active":
            reasons.append("key_revoked")
        try:
            secret = bytes.fromhex(key_entry.get("secret", ""))
        except ValueError:
            secret = None
            reasons.append("bad_key_secret")

    if secret is not None:
        expected = base64.urlsafe_b64encode(
            hmac.new(secret, _sig_line(obj).encode("utf-8"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_signature")

    profiles = policy.get("profiles") or {}
    profile = profiles.get(obj.get("profile"))
    if profile is None:
        reasons.append("unknown_profile")
    else:
        if not _valid_key_id(key_id):
            reasons.append("key_id_unsafe")
        elif not any(key_id.startswith(p) for p in profile.get("key_prefixes") or []):
            reasons.append("key_id_prefix")

        if obj.get("wrapping_key") not in (profile.get("wrapping_keys") or []):
            reasons.append("wrapping_key_mismatch")

        algorithms = profile.get("algorithms") or {}
        allowed_bytes = algorithms.get(obj.get("algorithm"))
        if allowed_bytes is None:
            reasons.append("algorithm_not_allowed")
        else:
            key_bytes = obj.get("key_bytes")
            if not isinstance(key_bytes, int) or isinstance(key_bytes, bool):
                reasons.append("key_bytes_invalid")
            elif key_bytes < int(policy.get("key_bytes_min", 1)) or key_bytes not in allowed_bytes:
                reasons.append("key_bytes_mismatch")

        usage = obj.get("usage")
        if not isinstance(usage, list) or not usage or not all(isinstance(u, str) for u in usage):
            reasons.append("usage_invalid")
        else:
            if policy.get("require_unique_usage", True) and len(set(usage)) != len(usage):
                reasons.append("usage_duplicate")
            usage_set = set(usage)
            if not set(profile.get("usage_required") or []).issubset(usage_set):
                reasons.append("usage_required_missing")
            if not usage_set.issubset(set(profile.get("usage_allowed") or [])):
                reasons.append("usage_not_allowed")

        if obj.get("encoding") not in (profile.get("encodings") or []):
            reasons.append("encoding_not_allowed")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_invalid")
    else:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat > now_unix + skew:
            reasons.append("iat_future")
        elif now_unix - iat > max_age:
            reasons.append("iat_stale")

    nonce = obj.get("nonce")
    items = store.get("items")
    if not isinstance(items, dict):
        items = {}
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "key_id": key_id}
    store["items"] = items
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "key_id": key_id}
