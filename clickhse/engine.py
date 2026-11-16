from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_q(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "database": obj.get("database"),
        "table": obj.get("table"),
        "user": obj.get("user"),
        "format": obj.get("format"),
        "nonce": obj.get("nonce"),
    }

def _deny(code: str, obj: dict) -> dict:
    return {"decision": "deny", "reason_codes": [code], "database": obj.get("database")}

def _sig_ok(obj: dict, secret_hex: str) -> bool:
    line = "v1|{kid}|{database}|{table}|{user}|{format}|{iat}|{nonce}".format(**obj)
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    expect = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return hmac.compare_digest(expect, str(obj.get("sig")))

def admit_q(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    fields = ("kid", "database", "table", "user", "format", "nonce", "sig")
    if any(not isinstance(obj.get(f), str) for f in fields) or not isinstance(obj.get("iat"), int):
        return _deny("bad_shape", obj)
    ident_deny = policy.get("ident_deny", [])
    if any(bad in obj["database"] or bad in obj["table"] for bad in ident_deny):
        return _deny("ident_deny", obj)
    user = policy.get("users", {}).get(obj["user"])
    if user is None:
        return _deny("user_unknown", obj)
    if obj["database"] not in user.get("databases", []):
        return _deny("db_not_allowed", obj)
    if obj["table"] not in user.get("tables", {}).get(obj["database"], []):
        return _deny("table_not_allowed", obj)
    if obj["format"] in policy.get("forbid_formats", []) or obj["format"] not in user.get("formats", []):
        return _deny("format_forbidden", obj)
    key = keys.get("keys", {}).get(obj["kid"])
    if key is None:
        return _deny("key_unknown", obj)
    if key.get("status") != "active":
        return _deny("key_revoked", obj)
    if not _sig_ok(obj, key["secret"]):
        return _deny("bad_sig", obj)
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if obj["iat"] > now_unix + skew:
        return _deny("iat_future", obj)
    if obj["iat"] < now_unix - max_age:
        return _deny("iat_stale", obj)
    items = store.setdefault("items", {})
    if obj["nonce"] in items:
        return _deny("replay", obj)
    items[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "database": obj["database"]}
