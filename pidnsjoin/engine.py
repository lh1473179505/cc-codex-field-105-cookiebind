from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_join(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "caller": obj.get("caller"),
        "target": obj.get("target"),
        "ns_inode": obj.get("ns_inode"),
        "fd_type": obj.get("fd_type"),
        "capability": obj.get("capability"),
        "nonce": obj.get("nonce"),
    }

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)

def _signed_message(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("caller")),
        str(obj.get("target")),
        str(obj.get("ns_inode")),
        str(obj.get("fd_type")),
        str(obj.get("capability")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _deny(obj: dict, reason: str) -> dict:
    return {"decision": "deny", "reason_codes": [reason], "target": obj.get("target")}

def admit_join(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if not isinstance(key_entry, dict):
        return _deny(obj, "unknown_kid")
    if key_entry.get("status") != "active":
        return _deny(obj, "key_revoked")

    secret = key_entry.get("secret")
    sig = obj.get("sig")
    if not isinstance(secret, str) or not isinstance(sig, str):
        return _deny(obj, "bad_signature")
    try:
        key_bytes = bytes.fromhex(secret)
    except ValueError:
        return _deny(obj, "bad_signature")
    expected = _b64url(hmac.new(key_bytes, _signed_message(obj).encode("utf-8"),
                                hashlib.sha256).digest())
    if not hmac.compare_digest(expected, sig):
        return _deny(obj, "bad_signature")

    caller = obj.get("caller")
    target = obj.get("target")
    caller_entry = policy.get("callers", {}).get(caller)
    if not isinstance(caller_entry, dict):
        return _deny(obj, "caller_not_authorized")

    namespace_inodes = policy.get("namespace_inodes", {})
    if target not in namespace_inodes:
        return _deny(obj, "target_unknown")
    if target not in caller_entry.get("targets", []):
        return _deny(obj, "target_not_allowed")
    if target in policy.get("forbidden_targets", []):
        return _deny(obj, "target_forbidden")
    if policy.get("forbid_self_join") and caller == target:
        return _deny(obj, "self_join_forbidden")

    ns_inode = obj.get("ns_inode")
    if not _is_int(ns_inode) or ns_inode < policy.get("ns_inode_min", 1):
        return _deny(obj, "inode_out_of_range")
    if ns_inode != namespace_inodes[target]:
        return _deny(obj, "inode_mismatch")

    fd_type = obj.get("fd_type")
    if fd_type not in policy.get("fd_types", []):
        return _deny(obj, "fd_type_not_allowed_global")
    if fd_type not in caller_entry.get("fd_types", []):
        return _deny(obj, "fd_type_not_allowed_caller")

    capability = obj.get("capability")
    if capability not in policy.get("capabilities", []):
        return _deny(obj, "capability_not_allowed_global")
    if capability != caller_entry.get("required_capability"):
        return _deny(obj, "capability_mismatch")

    iat = obj.get("iat")
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if (not _is_int(iat)
            or iat - now_unix > skew
            or now_unix - iat > max_age):
        return _deny(obj, "iat_outside_window")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or nonce == "":
        return _deny(obj, "invalid_nonce")
    if nonce in store.get("items", {}):
        return _deny(obj, "replayed_nonce")

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "target": target}
