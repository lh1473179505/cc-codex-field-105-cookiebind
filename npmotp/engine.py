from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_STRING_FIELDS = ("kid", "pkg", "otp", "user", "registry", "nonce", "sig")

def inspect_pub(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "pkg": obj.get("pkg"),
        "otp": obj.get("otp"),
        "user": obj.get("user"),
        "registry": obj.get("registry"),
        "nonce": obj.get("nonce"),
    }

def admit_pub(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    pkg = obj.get("pkg")
    reasons: list[str] = []

    if not _well_formed(obj):
        return {"decision": "deny", "reason_codes": ["malformed"], "pkg": pkg}

    scopes = policy.get("scopes", {})
    scope_cfg = None
    name = ""
    if "/" not in pkg:
        reasons.append("scope_unknown")
    else:
        scope, name = pkg.split("/", 1)
        scope_cfg = scopes.get(scope)
        if scope_cfg is None:
            reasons.append("scope_unknown")
        if not name:
            reasons.append("pkg_denied")

    for needle in policy.get("pkg_deny_substrings", []):
        if needle and needle in name:
            reasons.append("pkg_denied")
            break

    if scope_cfg is not None:
        if obj["user"] not in scope_cfg.get("users", []):
            reasons.append("user_denied")
        if obj["registry"] not in scope_cfg.get("registries", []):
            reasons.append("registry_denied")
        otp = obj["otp"]
        if len(otp) != scope_cfg.get("otp_len"):
            reasons.append("otp_length")
        if policy.get("otp_digits_only") and not _digits_only(otp):
            reasons.append("otp_chars")

    key_entry = keys.get("keys", {}).get(obj["kid"])
    if key_entry is None:
        reasons.append("unknown_kid")
    else:
        if key_entry.get("status") != "active":
            reasons.append("key_revoked")
        if not _signature_valid(obj, key_entry.get("secret", "")):
            reasons.append("bad_signature")

    age = now_unix - obj["iat"]
    skew = policy.get("clock_skew_seconds", 0)
    if age < -skew:
        reasons.append("iat_future")
    elif age > policy.get("max_age_seconds", 0) + skew:
        reasons.append("iat_expired")

    if obj["nonce"] in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "pkg": pkg}

    store.setdefault("items", {})[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "pkg": pkg}


def _well_formed(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    for field in _STRING_FIELDS:
        value = obj.get(field)
        if not isinstance(value, str) or not value:
            return False
    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return False
    return True


def _digits_only(value: str) -> bool:
    return all("0" <= char <= "9" for char in value)


def _signature_valid(obj: dict, secret_hex: str) -> bool:
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError:
        return False
    line = "|".join([
        "v1",
        obj["kid"],
        obj["pkg"],
        obj["otp"],
        obj["user"],
        obj["registry"],
        str(obj["iat"]),
        obj["nonce"],
    ])
    digest = hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest()
    sig = obj["sig"]
    try:
        provided = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(provided, digest)
