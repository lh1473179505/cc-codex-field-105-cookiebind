from __future__ import annotations
import base64
import binascii
import hashlib
import hmac

SIGNING_VERSION = "v1"
_REQUIRED_FIELDS = ("kid", "ns", "path", "caps", "wrap_ttl", "nonce", "iat", "sig")

def inspect_tok(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "ns": obj.get("ns"),
        "path": obj.get("path"),
        "caps": obj.get("caps"),
        "wrap_ttl": obj.get("wrap_ttl"),
        "nonce": obj.get("nonce"),
    }

def _signing_input(obj: dict) -> str:
    return "{ver}|{kid}|{ns}|{path}|{caps}|{wrap_ttl}|{iat}|{nonce}".format(
        ver=SIGNING_VERSION,
        kid=obj["kid"],
        ns=obj["ns"],
        path=obj["path"],
        caps=",".join(obj["caps"]),
        wrap_ttl=obj["wrap_ttl"],
        iat=obj["iat"],
        nonce=obj["nonce"],
    )

def _key_secret(key_entry: dict) -> bytes:
    raw = key_entry["secret"]
    try:
        return binascii.unhexlify(raw)
    except (ValueError, TypeError):
        return raw.encode("utf-8")

def _signature_ok(obj: dict, key_entry: dict) -> bool:
    digest = hmac.new(
        _key_secret(key_entry),
        _signing_input(obj).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    provided = str(obj.get("sig", "")).rstrip("=")
    return hmac.compare_digest(expected, provided)

def admit_tok(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    path = obj.get("path")
    reasons: list[str] = []

    if not isinstance(obj.get("caps"), list) or any(
        obj.get(field) is None for field in _REQUIRED_FIELDS
    ):
        return {"decision": "deny", "reason_codes": ["malformed_token"], "path": path}

    key_entry = keys.get("keys", {}).get(obj["kid"])
    if key_entry is None:
        reasons.append("unknown_kid")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    elif not _signature_ok(obj, key_entry):
        reasons.append("bad_sig")

    for deny_sub in policy.get("path_deny_substrings", []):
        if deny_sub in obj["path"]:
            reasons.append("path_deny_substring")
            break

    ns = obj["ns"]
    if ns not in policy.get("allowed_namespaces", []):
        reasons.append("namespace_denied")
    else:
        prefixes = policy.get("path_allow_prefixes", {}).get(ns, [])
        if not any(obj["path"].startswith(prefix) for prefix in prefixes):
            reasons.append("path_prefix_denied")

    caps = obj["caps"]
    caps_allow = set(policy.get("caps_allow", []))
    caps_max = set(policy.get("caps_max", []))
    if any(cap not in caps_allow for cap in caps):
        reasons.append("cap_not_allowed")
    if not set(caps).issubset(caps_max):
        reasons.append("cap_exceeds_max")
    if policy.get("forbid_sudo") and "sudo" in caps:
        reasons.append("sudo_forbidden")

    try:
        wrap_ttl = int(obj["wrap_ttl"])
    except (TypeError, ValueError):
        reasons.append("wrap_ttl_invalid")
    else:
        if wrap_ttl > int(policy.get("wrap_ttl_max", 0)):
            reasons.append("wrap_ttl_exceeded")

    try:
        iat = int(obj["iat"])
    except (TypeError, ValueError):
        reasons.append("iat_invalid")
    else:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if now_unix < iat - skew or now_unix > iat + max_age:
            reasons.append("time_window")

    if obj["nonce"] in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "path": path}

    store.setdefault("items", {})[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "path": path}
