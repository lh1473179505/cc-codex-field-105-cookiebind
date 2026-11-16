from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_cg(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "path": obj.get("path"),
        "controllers": obj.get("controllers"),
        "memory_max": obj.get("memory_max"),
        "cpu_weight": obj.get("cpu_weight"),
        "nonce": obj.get("nonce"),
    }


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def admit_cg(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    path = obj.get("path")
    controllers = obj.get("controllers")
    memory_max = obj.get("memory_max")
    cpu_weight = obj.get("cpu_weight")
    iat = obj.get("iat")
    nonce = obj.get("nonce")
    kid = obj.get("kid")
    sig = obj.get("sig")
    reasons: list[str] = []

    controllers_ok = isinstance(controllers, list) and all(isinstance(c, str) for c in controllers)
    well_formed = (
        isinstance(path, str)
        and path != ""
        and controllers_ok
        and _is_int(memory_max)
        and _is_int(cpu_weight)
        and _is_int(iat)
        and isinstance(nonce, str)
        and nonce != ""
        and isinstance(kid, str)
        and kid != ""
        and isinstance(sig, str)
        and sig != ""
    )
    if not well_formed:
        reasons.append("malformed_cg")

    if isinstance(path, str) and path != "":
        for denied in policy.get("path_deny_substrings", []):
            if denied in path:
                reasons.append("path_deny_substring")
                break
        else:
            prefixes = policy.get("path_allow_prefixes", [])
            if not any(path.startswith(prefix) for prefix in prefixes):
                reasons.append("path_prefix_denied")

    if controllers_ok:
        actual = set(controllers)
        allowed = set(policy.get("controllers_allow", []))
        required = set(policy.get("controllers_required", []))
        if not actual <= allowed:
            reasons.append("controller_not_allowed")
        if not required <= actual:
            reasons.append("required_controller_missing")

    if _is_int(memory_max):
        if not (policy["memory_max_min"] <= memory_max <= policy["memory_max_max"]):
            reasons.append("memory_max_out_of_range")
    if _is_int(cpu_weight):
        if not (policy["cpu_weight_min"] <= cpu_weight <= policy["cpu_weight_max"]):
            reasons.append("cpu_weight_out_of_range")

    key_entry = None
    if isinstance(kid, str) and kid != "":
        key_entry = keys.get("keys", {}).get(kid)
        if key_entry is None:
            reasons.append("unknown_kid")
        elif key_entry.get("status") != "active":
            reasons.append("key_revoked")

    if well_formed and key_entry is not None:
        try:
            secret = bytes.fromhex(key_entry["secret"])
        except (KeyError, TypeError, ValueError):
            reasons.append("bad_signature")
        else:
            message = "|".join([
                "v1",
                kid,
                path,
                ",".join(controllers),
                str(memory_max),
                str(cpu_weight),
                str(iat),
                nonce,
            ]).encode("utf-8")
            expected = _b64url(hmac.new(secret, message, hashlib.sha256).digest())
            if not hmac.compare_digest(expected, sig):
                reasons.append("bad_signature")

    if _is_int(iat):
        age = now_unix - iat
        if age > policy.get("max_age_seconds", 0) or age < -policy.get("clock_skew_seconds", 0):
            reasons.append("iat_out_of_window")

    if isinstance(nonce, str) and nonce != "" and nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "path": path}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "path": path}
