from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_VERSION = "v1"
_STRING_FIELDS = (
    "kid",
    "typ",
    "aud",
    "sub",
    "claim_path",
    "claim_val",
    "nonce",
    "sig",
)
_INT_FIELDS = ("iat", "exp")


def _deny(sub: Any, reason: str) -> dict:
    return {"decision": "deny", "reason_codes": [reason], "sub": sub}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _signing_input(obj: dict) -> str:
    crit_csv = ",".join(obj["crit"])
    return "|".join(
        [
            _VERSION,
            obj["kid"],
            obj["typ"],
            crit_csv,
            obj["aud"],
            obj["sub"],
            obj["claim_path"],
            obj["claim_val"],
            str(obj["iat"]),
            str(obj["exp"]),
            obj["nonce"],
        ]
    )

def inspect_token(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "typ": obj.get("typ"),
        "crit": obj.get("crit"),
        "aud": obj.get("aud"),
        "sub": obj.get("sub"),
        "claim_path": obj.get("claim_path"),
        "claim_val": obj.get("claim_val"),
        "nonce": obj.get("nonce"),
    }

def admit_token(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    if not isinstance(obj, dict):
        return _deny(None, "malformed_token")
    sub = obj.get("sub")

    for field in _STRING_FIELDS:
        if not isinstance(obj.get(field), str) or obj[field] == "":
            return _deny(sub, "malformed_token")
    for field in _INT_FIELDS:
        value = obj.get(field)
        if not isinstance(value, int) or isinstance(value, bool):
            return _deny(sub, "malformed_token")
    crit = obj.get("crit")
    if not isinstance(crit, list) or not crit or not all(isinstance(name, str) and name for name in crit):
        return _deny(sub, "malformed_token")

    key_entries = keys.get("keys") if isinstance(keys, dict) else None
    key_entry = key_entries.get(obj["kid"]) if isinstance(key_entries, dict) else None
    if not isinstance(key_entry, dict):
        return _deny(sub, "unknown_kid")
    if key_entry.get("status") != "active":
        return _deny(sub, "key_revoked")
    try:
        secret = bytes.fromhex(key_entry["secret"])
    except (KeyError, TypeError, ValueError):
        return _deny(sub, "key_misconfigured")

    expected_sig = _b64url(
        hmac.new(secret, _signing_input(obj).encode("utf-8"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(expected_sig, obj["sig"]):
        return _deny(sub, "bad_signature")

    allowed_crit = policy.get("allowed_crit", [])
    crit_set = set(crit)
    if len(crit_set) != len(crit) or any(name not in allowed_crit for name in crit):
        return _deny(sub, "crit_not_allowed")
    if policy.get("require_all_crit") and not set(allowed_crit).issubset(crit_set):
        return _deny(sub, "crit_missing")

    if obj["typ"] not in policy.get("allowed_typ", []):
        return _deny(sub, "typ_not_allowed")
    if obj["aud"] not in policy.get("allowed_audiences", []):
        return _deny(sub, "aud_not_allowed")
    sub_prefixes = policy.get("sub_prefixes", [])
    if not any(obj["sub"].startswith(prefix) for prefix in sub_prefixes):
        return _deny(sub, "sub_prefix_denied")

    claim_path = obj["claim_path"]
    if policy.get("forbid_path_dots_escape") and ".." in claim_path:
        return _deny(sub, "path_escape_denied")
    if claim_path not in policy.get("claim_path_allow", []):
        return _deny(sub, "path_not_allowed")
    allowed_values = policy.get("claim_values", {}).get(claim_path)
    if not isinstance(allowed_values, list) or obj["claim_val"] not in allowed_values:
        return _deny(sub, "claim_val_not_allowed")

    now = int(now_unix)
    skew = int(policy.get("clock_skew_seconds", 0))
    if obj["iat"] > now + skew:
        return _deny(sub, "iat_in_future")
    if now > obj["exp"] + skew:
        return _deny(sub, "token_expired")
    max_age = policy.get("max_age_seconds")
    if max_age is not None and now - obj["iat"] > int(max_age) + skew:
        return _deny(sub, "token_too_old")

    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        return _deny(sub, "store_misconfigured")
    items = store["items"]
    if obj["nonce"] in items:
        return _deny(sub, "nonce_replayed")

    items[obj["nonce"]] = {"ts": now}
    return {"decision": "allow", "reason_codes": [], "sub": sub}
