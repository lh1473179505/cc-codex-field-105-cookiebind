from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

def inspect_proposal(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "local_id": obj.get("local_id"),
        "peer_id": obj.get("peer_id"),
        "local_cidr": obj.get("local_cidr"),
        "remote_cidr": obj.get("remote_cidr"),
        "esp": obj.get("esp"),
        "ike": obj.get("ike"),
        "pfs": obj.get("pfs"),
        "lifetime": obj.get("lifetime"),
        "nonce": obj.get("nonce"),
    }

def _sig_line(obj: dict) -> str:
    fields = ("kid", "profile", "local_id", "peer_id", "local_cidr",
              "remote_cidr", "esp", "ike", "pfs", "lifetime", "iat", "nonce")
    return "v1|" + "|".join(str(obj.get(f)) for f in fields)

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"),
                      hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _check_selector(value: Any, supernets: list, side: str,
                    forbid_default: bool, codes: list) -> None:
    try:
        net = ipaddress.ip_network(value, strict=True)
    except (ValueError, TypeError):
        codes.append(f"{side}_selector_invalid")
        return
    if forbid_default and net.prefixlen == 0:
        codes.append(f"{side}_selector_default_route")
        return
    for sup in supernets:
        try:
            sup_net = ipaddress.ip_network(sup, strict=True)
        except ValueError:
            continue
        if net.version == sup_net.version and net.subnet_of(sup_net):
            return
    codes.append(f"{side}_selector_not_covered")

def admit_proposal(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list = []
    profile_name = obj.get("profile")
    profiles = policy.get("profiles", {})
    profile = profiles.get(profile_name)
    if profile is None:
        return {"decision": "deny", "reason_codes": ["profile_unknown"],
                "profile": profile_name}

    if obj.get("local_id") != profile.get("local_id"):
        codes.append("local_id_mismatch")
    if obj.get("peer_id") not in profile.get("peer_ids", []):
        codes.append("peer_not_allowed")

    forbid_default = bool(policy.get("forbid_default_route", True))
    _check_selector(obj.get("local_cidr"), profile.get("local_supernets", []),
                    "local", forbid_default, codes)
    _check_selector(obj.get("remote_cidr"), profile.get("remote_supernets", []),
                    "remote", forbid_default, codes)

    if obj.get("esp") not in profile.get("esp", []):
        codes.append("esp_not_allowed")
    if obj.get("ike") not in profile.get("ike", []):
        codes.append("ike_not_allowed")
    if obj.get("pfs") not in profile.get("pfs", []):
        codes.append("pfs_not_allowed")
    lifetime = obj.get("lifetime")
    if (not isinstance(lifetime, int) or isinstance(lifetime, bool)
            or not profile.get("lifetime_min", 0) <= lifetime <= profile.get("lifetime_max", 0)):
        codes.append("lifetime_out_of_range")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid)
    if key is None:
        codes.append("key_unknown")
    elif key.get("status") != "active":
        codes.append("key_not_active")
    else:
        expected = _expected_sig(key["secret"], _sig_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            codes.append("bad_signature")

    iat = obj.get("iat")
    if (not isinstance(iat, int) or isinstance(iat, bool)
            or iat > now_unix + policy.get("clock_skew_seconds", 0)
            or iat < now_unix - policy.get("max_age_seconds", 0)):
        codes.append("iat_out_of_window")

    nonce = obj.get("nonce")
    items = store.get("items")
    if not isinstance(items, dict):
        items = {}
    if nonce in items:
        codes.append("nonce_replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "profile": profile_name}
    items[nonce] = {"ts": now_unix}
    store["items"] = items
    return {"decision": "allow", "reason_codes": [], "profile": profile_name}
