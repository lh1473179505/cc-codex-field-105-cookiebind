from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_sig(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "sid": obj.get("sid"),
        "proto": obj.get("proto"),
        "msg": obj.get("msg"),
        "content": obj.get("content"),
        "nonce": obj.get("nonce"),
    }

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _signing_string(obj: dict) -> str:
    return "v1|{kid}|{sid}|{proto}|{msg}|{content}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        sid=obj.get("sid"),
        proto=obj.get("proto"),
        msg=obj.get("msg"),
        content=obj.get("content"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def admit_sig(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []

    sid = obj.get("sid")
    if not isinstance(sid, int) or isinstance(sid, bool) or not any(
        lo <= sid <= hi for lo, hi in policy.get("sid_ranges", [])
    ):
        reasons.append("sid_range")

    if obj.get("proto") not in policy.get("protos", []):
        reasons.append("proto")

    msg = obj.get("msg")
    if not isinstance(msg, str) or not any(
        msg.startswith(p) for p in policy.get("msg_prefixes", [])
    ):
        reasons.append("msg_prefix")

    content = obj.get("content")
    if not isinstance(content, str):
        reasons.append("content_len")
    else:
        if len(content) > policy.get("content_max_len", 0):
            reasons.append("content_len")
        if any(sub in content for sub in policy.get("content_deny_substrings", [])):
            reasons.append("content_deny")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid)
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        expected = hmac.new(
            bytes.fromhex(key["secret"]),
            _signing_string(obj).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        try:
            given = _b64url_decode(str(obj.get("sig", "")))
        except Exception:
            given = b""
        if not hmac.compare_digest(expected, given):
            reasons.append("bad_sig")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce")
    elif nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "sid": obj.get("sid")}

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "sid": obj.get("sid")}
