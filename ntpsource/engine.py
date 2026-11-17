from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

def inspect_source(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "hostname": obj.get("hostname"),
        "ip_address": obj.get("ip_address"),
        "stratum": obj.get("stratum"),
        "refid": obj.get("refid"),
        "minpoll": obj.get("minpoll"),
        "maxpoll": obj.get("maxpoll"),
        "auth_key": obj.get("auth_key"),
        "nonce": obj.get("nonce"),
    }

def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)

def _signing_string(obj: dict) -> str:
    fields = (
        "kid", "profile", "hostname", "ip_address", "stratum", "refid",
        "minpoll", "maxpoll", "auth_key", "iat", "nonce",
    )
    return "v1|" + "|".join(str(obj.get(f)) for f in fields)

def _expected_sig(secret_hex: str, obj: dict) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex), _signing_string(obj).encode("utf-8"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_source(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    profiles = policy.get("profiles", {})
    profile = profiles.get(obj.get("profile"))
    if profile is None:
        reasons.append("profile_unknown")
        profile = {}

    if obj.get("hostname") != profile.get("hostname"):
        reasons.append("hostname_mismatch")

    try:
        addr = ipaddress.ip_address(obj.get("ip_address", ""))
    except ValueError:
        reasons.append("ip_syntax")
    else:
        if not any(addr in ipaddress.ip_network(c) for c in profile.get("ip_cidrs", [])):
            reasons.append("ip_cidr")

    stratum = obj.get("stratum")
    if not _is_int(stratum) or stratum not in profile.get("strata", []):
        reasons.append("stratum")

    refid = obj.get("refid")
    if not isinstance(refid, str) or refid not in profile.get("refids", []):
        reasons.append("refid")

    minpoll = obj.get("minpoll")
    maxpoll = obj.get("maxpoll")
    lo = policy.get("poll_exponent_min")
    hi = policy.get("poll_exponent_max")
    p_lo = profile.get("poll_min")
    p_hi = profile.get("poll_max")
    for name, val in (("minpoll", minpoll), ("maxpoll", maxpoll)):
        if (
            not _is_int(val)
            or (lo is not None and val < lo)
            or (hi is not None and val > hi)
            or (p_lo is not None and val < p_lo)
            or (p_hi is not None and val > p_hi)
        ):
            reasons.append(name)
    if policy.get("require_poll_order", True) and _is_int(minpoll) and _is_int(maxpoll):
        if minpoll > maxpoll:
            reasons.append("poll_order")

    if obj.get("auth_key") not in profile.get("auth_keys", []):
        reasons.append("auth_key")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if key_entry is None:
        reasons.append("kid_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    elif not hmac.compare_digest(_expected_sig(key_entry["secret"], obj), str(obj.get("sig"))):
        reasons.append("bad_sig")

    iat = obj.get("iat")
    if not _is_int(iat):
        reasons.append("iat")
    else:
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")
        if iat - now_unix > policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce")
    elif nonce in store.get("items", {}):
        reasons.append("replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "hostname": obj.get("hostname")}
    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "hostname": obj.get("hostname")}
