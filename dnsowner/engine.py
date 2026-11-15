from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_rr(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "owner": obj.get("owner"),
        "rrtype": obj.get("rrtype"),
        "rdata": obj.get("rdata"),
        "ttl": obj.get("ttl"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{owner}|{rrtype}|{rdata}|{ttl}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        owner=obj.get("owner"),
        rrtype=obj.get("rrtype"),
        rdata=obj.get("rdata"),
        ttl=obj.get("ttl"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _zone_match(owner: str, zones: list) -> bool:
    for zone in zones:
        if owner == zone:
            return True
        if owner.endswith(zone) and len(owner) > len(zone) and owner[-len(zone) - 1] == ".":
            return True
    return False

def admit_rr(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    owner = obj.get("owner")
    rrtype = obj.get("rrtype")
    rdata = obj.get("rdata")
    ttl = obj.get("ttl")
    iat = obj.get("iat")
    nonce = obj.get("nonce")
    kid = obj.get("kid")

    if not isinstance(owner, str) or not owner:
        reasons.append("owner_invalid")
    else:
        if policy.get("require_lowercase") and owner != owner.lower():
            reasons.append("owner_not_lowercase")
        if policy.get("require_absolute") and not owner.endswith("."):
            reasons.append("owner_not_absolute")
        if policy.get("forbid_empty_label") and (
            ".." in owner or owner.startswith(".")
        ):
            reasons.append("owner_empty_label")
        if not _zone_match(owner, policy.get("allowed_zones", [])):
            reasons.append("owner_zone")

    if rrtype not in policy.get("allowed_types", []):
        reasons.append("rrtype_not_allowed")

    if not isinstance(ttl, int) or isinstance(ttl, bool) or not (
        policy.get("ttl_min", 0) <= ttl <= policy.get("ttl_max", 2**31)
    ):
        reasons.append("ttl_out_of_range")

    if rrtype == "TXT":
        prefixes = policy.get("txt_prefix_allow", [])
        if not isinstance(rdata, str) or not any(rdata.startswith(p) for p in prefixes):
            reasons.append("txt_prefix_not_allowed")

    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("kid_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        expected = _expected_sig(key_entry["secret"], _signing_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_signature")

    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_in_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_too_old")

    items = store.setdefault("items", {})
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "owner": owner}

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "owner": owner}
