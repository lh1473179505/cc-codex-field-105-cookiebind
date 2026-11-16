from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_job(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "app": obj.get("app"),
        "user": obj.get("user"),
        "master": obj.get("master"),
        "jars": obj.get("jars"),
        "nonce": obj.get("nonce"),
    }


_REQUIRED_FIELDS = ("kid", "app", "user", "master", "jars", "iat", "nonce", "sig")


def _deny(app: Any, *reason_codes: str) -> dict:
    return {"decision": "deny", "reason_codes": list(reason_codes), "app": app}


def _signing_payload(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj["kid"]),
        str(obj["app"]),
        str(obj["user"]),
        str(obj["master"]),
        str(obj["jars"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ])


def _expected_signature(obj: dict, secret_hex: str) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        _signing_payload(obj).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def admit_job(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    app = obj.get("app")

    if any(field not in obj for field in _REQUIRED_FIELDS):
        return _deny(app, "malformed_job")
    if not all(isinstance(obj[field], str) and obj[field]
               for field in ("kid", "app", "user", "master", "jars", "nonce", "sig")):
        return _deny(app, "malformed_job")
    if isinstance(obj["iat"], bool) or not isinstance(obj["iat"], int):
        return _deny(app, "malformed_job")

    keyring = keys.get("keys", {})
    key_entry = keyring.get(obj["kid"])
    if not isinstance(key_entry, dict):
        return _deny(app, "unknown_kid")
    if key_entry.get("status") != "active":
        return _deny(app, "key_revoked")

    try:
        expected = _expected_signature(obj, key_entry["secret"])
    except (KeyError, ValueError):
        return _deny(app, "bad_signature")
    if not hmac.compare_digest(expected, obj["sig"]):
        return _deny(app, "bad_signature")

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if obj["iat"] > now_unix + skew:
        return _deny(app, "future_iat")
    if now_unix - obj["iat"] > max_age:
        return _deny(app, "stale_iat")

    app_entry = policy.get("apps", {}).get(obj["app"])
    if not isinstance(app_entry, dict):
        return _deny(app, "unknown_app")
    if obj["user"] not in app_entry.get("users", []):
        return _deny(app, "user_denied")
    if obj["master"] not in app_entry.get("masters", []):
        return _deny(app, "master_denied")

    jars = obj["jars"]
    for deny_substring in policy.get("jar_deny_substrings", []):
        if deny_substring in jars:
            return _deny(app, "jar_deny_substring")
    if not any(jars.startswith(prefix) for prefix in app_entry.get("jar_prefixes", [])):
        return _deny(app, "jar_prefix_denied")

    used_nonces = store.setdefault("items", {})
    if obj["nonce"] in used_nonces:
        return _deny(app, "nonce_replayed")

    used_nonces[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "app": app}
