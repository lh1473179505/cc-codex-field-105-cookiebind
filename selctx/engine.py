from __future__ import annotations
import base64
import binascii
import hashlib
import hmac

SIGNING_VERSION = "v1"
_STRING_FIELDS = ("kid", "user", "role", "type", "range", "path", "nonce", "sig")

def inspect_ctx(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "role": obj.get("role"),
        "type": obj.get("type"),
        "range": obj.get("range"),
        "path": obj.get("path"),
        "nonce": obj.get("nonce"),
    }


def _deny(obj: dict, reason_code: str) -> dict:
    return {
        "decision": "deny",
        "reason_codes": [reason_code],
        "type": obj.get("type"),
    }


def _signing_input(obj: dict) -> bytes:
    return "|".join([
        SIGNING_VERSION,
        str(obj["kid"]),
        str(obj["user"]),
        str(obj["role"]),
        str(obj["type"]),
        str(obj["range"]),
        str(obj["path"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ]).encode("utf-8")


def _decode_sig(sig: str) -> bytes | None:
    try:
        return base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    except (binascii.Error, ValueError):
        return None


def admit_ctx(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    if not isinstance(obj, dict):
        return {"decision": "deny", "reason_codes": ["malformed"], "type": None}

    for field in _STRING_FIELDS:
        if not isinstance(obj.get(field), str) or not obj[field]:
            return _deny(obj, "malformed")
    if not isinstance(obj.get("iat"), int) or isinstance(obj.get("iat"), bool):
        return _deny(obj, "malformed")

    path = obj["path"]

    # Path traversal is rejected before any type/prefix binding is consulted.
    for deny_substring in policy.get("path_deny_substrings", []):
        if deny_substring in path:
            return _deny(obj, "path_traversal")

    ctx_type = obj["type"]
    if ctx_type not in policy.get("allowed_types", []):
        return _deny(obj, "type_denied")

    prefixes = policy.get("type_path_prefixes", {}).get(ctx_type, [])
    if not any(path.startswith(prefix) for prefix in prefixes):
        return _deny(obj, "path_denied")

    if obj["user"] not in policy.get("allowed_users", []):
        return _deny(obj, "user_denied")
    if obj["role"] not in policy.get("allowed_roles", []):
        return _deny(obj, "role_denied")
    if obj["range"] not in policy.get("range_allow", []):
        return _deny(obj, "range_denied")

    key_entry = keys.get("keys", {}).get(obj["kid"])
    if not isinstance(key_entry, dict) or not isinstance(key_entry.get("secret"), str):
        return _deny(obj, "unknown_kid")
    try:
        secret = bytes.fromhex(key_entry["secret"])
    except ValueError:
        return _deny(obj, "unknown_kid")

    expected_sig = hmac.new(
        secret, _signing_input(obj), hashlib.sha256
    ).digest()
    provided_sig = _decode_sig(obj["sig"])
    if provided_sig is None or not hmac.compare_digest(expected_sig, provided_sig):
        return _deny(obj, "bad_signature")

    if key_entry.get("status") != "active":
        return _deny(obj, "key_revoked")

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    iat = obj["iat"]
    if iat - now_unix > skew:
        return _deny(obj, "iat_future")
    if now_unix - iat > max_age + skew:
        return _deny(obj, "iat_expired")

    items = store.get("items")
    if not isinstance(items, dict) or obj["nonce"] in items:
        return _deny(obj, "nonce_replay")

    # The store is mutated only when every gate passes; deny paths never touch it.
    items[obj["nonce"]] = {"ts": iat}
    return {"decision": "allow", "reason_codes": [], "type": ctx_type}
