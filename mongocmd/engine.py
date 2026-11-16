from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_op(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "db": obj.get("db"),
        "cmd": obj.get("cmd"),
        "coll": obj.get("coll"),
        "user": obj.get("user"),
        "nonce": obj.get("nonce"),
    }

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{db}|{cmd}|{coll}|{user}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        db=obj.get("db"),
        cmd=obj.get("cmd"),
        coll=obj.get("coll"),
        user=obj.get("user"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def admit_op(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    cmd = obj.get("cmd")
    db = obj.get("db")
    coll = obj.get("coll")
    user = obj.get("user")
    kid = obj.get("kid")
    nonce = obj.get("nonce")

    key = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if key is None:
        reasons.append("unknown_key")
    elif key.get("status") != "active":
        reasons.append("key_revoked")

    if key is not None:
        expected_sig = None
        try:
            secret = bytes.fromhex(key["secret"])
            digest = hmac.new(
                secret,
                _signing_line(obj).encode("utf-8"),
                hashlib.sha256,
            ).digest()
            expected_sig = _b64url(digest)
        except (TypeError, ValueError, KeyError):
            expected_sig = None
        sig = obj.get("sig")
        if (
            not isinstance(sig, str)
            or expected_sig is None
            or not hmac.compare_digest(expected_sig, sig)
        ):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_invalid")
    else:
        age = now_unix - iat
        if age > policy.get("max_age_seconds", 0):
            reasons.append("token_expired")
        elif age < -policy.get("clock_skew_seconds", 0):
            reasons.append("time_skew")

    if isinstance(db, str) and isinstance(coll, str):
        if any(ch in db or ch in coll for ch in policy.get("ident_deny", [])):
            reasons.append("ident_denied")

    user_policy = policy.get("users", {}).get(user) if isinstance(user, str) else None
    if user_policy is None:
        reasons.append("user_denied")
    else:
        if db not in user_policy.get("dbs", []):
            reasons.append("db_denied")
        if coll not in user_policy.get("colls", {}).get(db, []):
            reasons.append("coll_denied")
        if cmd not in user_policy.get("cmds", []):
            reasons.append("cmd_denied")

    if cmd in policy.get("forbid_cmds", []):
        reasons.append("cmd_forbidden")

    items = store.get("items")
    if not isinstance(items, dict):
        items = {}
        store["items"] = items
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "cmd": cmd}

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "cmd": cmd}
