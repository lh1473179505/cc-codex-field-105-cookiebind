from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

SIGNING_VERSION = "v1"
_RULE_FIELDS = ("kid", "principal", "ns", "path", "method", "iat", "nonce", "sig")

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "principal": obj.get("principal"),
        "ns": obj.get("ns"),
        "path": obj.get("path"),
        "method": obj.get("method"),
        "nonce": obj.get("nonce"),
    }


def _deny(obj: dict, reason_code: str) -> dict:
    principal = obj.get("principal")
    return {
        "decision": "deny",
        "reason_codes": [reason_code],
        "principal": principal if isinstance(principal, str) else "",
    }


def _well_formed(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    for field in _RULE_FIELDS:
        if field not in obj:
            return False
    for field in ("kid", "principal", "ns", "path", "method", "nonce", "sig"):
        if not isinstance(obj[field], str) or not obj[field]:
            return False
    iat = obj["iat"]
    return isinstance(iat, int) and not isinstance(iat, bool)


def _signing_line(obj: dict) -> str:
    return "|".join((
        SIGNING_VERSION,
        obj["kid"],
        obj["principal"],
        obj["ns"],
        obj["path"],
        obj["method"],
        str(obj["iat"]),
        obj["nonce"],
    ))


def _expected_signature(secret_hex: str, signing_line: str) -> str:
    key = bytes.fromhex(secret_hex)
    digest = hmac.new(key, signing_line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _path_is_listed(path: str, allowed_paths: list) -> bool:
    for entry in allowed_paths:
        if not isinstance(entry, str):
            continue
        if path == entry or path.startswith(entry):
            return True
        if entry.endswith("/") and path == entry.rstrip("/"):
            return True
    return False


def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    if not _well_formed(obj):
        return _deny(obj if isinstance(obj, dict) else {}, "malformed_rule")

    principals = policy.get("principals", {})
    entry = principals.get(obj["principal"])
    if not isinstance(entry, dict):
        return _deny(obj, "principal_unknown")

    if obj["ns"] not in entry.get("ns", []):
        return _deny(obj, "ns_denied")

    lowered_path = obj["path"].lower()
    for blocked in policy.get("path_deny_substrings", []):
        if isinstance(blocked, str) and blocked.lower() in lowered_path:
            return _deny(obj, "path_deny")

    if not _path_is_listed(obj["path"], entry.get("paths", [])):
        return _deny(obj, "path_denied")

    if obj["method"] not in entry.get("methods", []):
        return _deny(obj, "method_denied")

    key_entry = keys.get("keys", {}).get(obj["kid"])
    if not isinstance(key_entry, dict):
        return _deny(obj, "key_unknown")
    if key_entry.get("status") != "active":
        return _deny(obj, "key_revoked")

    try:
        expected = _expected_signature(key_entry["secret"], _signing_line(obj))
    except (KeyError, ValueError):
        return _deny(obj, "bad_signature")
    if not hmac.compare_digest(expected, obj["sig"]):
        return _deny(obj, "bad_signature")

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if obj["iat"] > now_unix + skew:
        return _deny(obj, "token_future")
    if obj["iat"] < now_unix - max_age:
        return _deny(obj, "token_expired")

    items = store.get("items")
    if not isinstance(items, dict):
        items = {}
        store["items"] = items
    if obj["nonce"] in items:
        return _deny(obj, "nonce_replayed")

    items[obj["nonce"]] = {"ts": now_unix}
    return {
        "decision": "allow",
        "reason_codes": [],
        "principal": obj["principal"],
    }
