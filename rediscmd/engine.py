from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_op(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "cmd": obj.get("cmd"),
        "key": obj.get("key"),
        "channel": obj.get("channel"),
        "arity": obj.get("arity"),
        "nonce": obj.get("nonce"),
    }

def _signing_input(obj: dict) -> bytes:
    parts = [
        "v1",
        obj.get("kid"),
        obj.get("cmd"),
        obj.get("key"),
        obj.get("channel"),
        obj.get("arity"),
        obj.get("iat"),
        obj.get("nonce"),
    ]
    return "|".join("" if part is None else str(part) for part in parts).encode("utf-8")

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _deny(obj: dict, code: str) -> dict:
    return {"decision": "deny", "reason_codes": [code], "cmd": obj.get("cmd")}

def admit_op(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    cmd = obj.get("cmd")
    key = obj.get("key")
    channel = obj.get("channel")

    key_text = key if isinstance(key, str) else ""
    for bad in policy.get("key_deny_substrings", []):
        if bad in key_text:
            return _deny(obj, "key_denied_pattern")
    if not any(key_text.startswith(prefix) for prefix in policy.get("key_allow_prefixes", [])):
        return _deny(obj, "key_prefix_denied")

    if cmd not in policy.get("allowed_cmds", []):
        return _deny(obj, "cmd_not_allowed")

    if obj.get("arity") != policy.get("cmd_arity", {}).get(cmd):
        return _deny(obj, "arity_mismatch")

    if policy.get("publish_requires_channel") and cmd == "PUBLISH":
        channel_text = channel if isinstance(channel, str) else ""
        if not channel_text:
            return _deny(obj, "channel_empty")
        if not any(channel_text.startswith(prefix) for prefix in policy.get("channel_allow_prefixes", [])):
            return _deny(obj, "channel_prefix_denied")

    kid = obj.get("kid")
    entry = keys.get("keys", {}).get(kid)
    if not isinstance(entry, dict):
        return _deny(obj, "kid_unknown")
    if entry.get("status") != "active":
        return _deny(obj, "kid_revoked")
    try:
        secret = bytes.fromhex(entry.get("secret", ""))
        expected = _b64url(hmac.new(secret, _signing_input(obj), hashlib.sha256).digest())
    except (TypeError, ValueError):
        return _deny(obj, "bad_signature")
    sig = obj.get("sig")
    if not isinstance(sig, str) or not hmac.compare_digest(expected, sig):
        return _deny(obj, "bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        return _deny(obj, "iat_invalid")
    skew = policy.get("clock_skew_seconds", 0)
    if iat > now_unix + skew:
        return _deny(obj, "iat_future")
    if iat < now_unix - policy.get("max_age_seconds", 0) - skew:
        return _deny(obj, "iat_expired")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return _deny(obj, "nonce_missing")
    if nonce in store.get("items", {}):
        return _deny(obj, "nonce_replay")

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "cmd": cmd}
