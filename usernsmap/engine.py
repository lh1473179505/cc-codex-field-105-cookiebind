from __future__ import annotations
import base64
import hashlib
import hmac
import posixpath
from typing import Any

def inspect_mapping(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "parent_ns": obj.get("parent_ns"),
        "container_uid": obj.get("container_uid"),
        "container_gid": obj.get("container_gid"),
        "host_uid_start": obj.get("host_uid_start"),
        "host_gid_start": obj.get("host_gid_start"),
        "length": obj.get("length"),
        "newuidmap": obj.get("newuidmap"),
        "nonce": obj.get("nonce"),
    }

def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)

def _mac_line(obj: dict) -> str:
    helpers = obj.get("newuidmap")
    helper_str = ",".join(f"{k}={helpers[k]}" for k in sorted(helpers))
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("parent_ns")),
        str(obj.get("container_uid")),
        str(obj.get("container_gid")),
        str(obj.get("host_uid_start")),
        str(obj.get("host_gid_start")),
        str(obj.get("length")),
        helper_str,
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _expected_sig(obj: dict, secret_hex: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), _mac_line(obj).encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def _contained(start: int, length: int, ranges: list) -> bool:
    end = start + length  # half-open [start, end)
    for lo, hi in ranges:
        if lo <= start and end - 1 <= hi:
            return True
    return False

def admit_mapping(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    parent_ns = obj.get("parent_ns")

    if not isinstance(parent_ns, str) or not parent_ns:
        reasons.append("parent_ns_invalid")
        parent = None
    elif parent_ns != posixpath.normpath(parent_ns):
        reasons.append("parent_ns_traversal")
        parent = None
    else:
        parent = policy.get("parents", {}).get(parent_ns)
        if parent is None:
            reasons.append("parent_ns_unknown")

    c_uid = obj.get("container_uid")
    c_gid = obj.get("container_gid")
    length = obj.get("length")
    h_uid = obj.get("host_uid_start")
    h_gid = obj.get("host_gid_start")
    helpers = obj.get("newuidmap")

    if parent is not None:
        if not _is_int(c_uid) or not (parent["container_uid_min"] <= c_uid <= parent["container_uid_max"]):
            reasons.append("container_uid_range")
        if not _is_int(c_gid) or not (parent["container_gid_min"] <= c_gid <= parent["container_gid_max"]):
            reasons.append("container_gid_range")
        if not _is_int(length) or not (parent["length_min"] <= length <= parent["length_max"]):
            reasons.append("length_range")
        if _is_int(h_uid) and _is_int(length) and length >= 1:
            if not _contained(h_uid, length, parent["host_uid_ranges"]):
                reasons.append("host_uid_range")
        else:
            reasons.append("host_uid_range")
        if _is_int(h_gid) and _is_int(length) and length >= 1:
            if not _contained(h_gid, length, parent["host_gid_ranges"]):
                reasons.append("host_gid_range")
        else:
            reasons.append("host_gid_range")
        if (
            policy.get("require_distinct_uid_gid_ranges")
            and _is_int(h_uid) and _is_int(h_gid) and _is_int(length) and length >= 1
            and "host_uid_range" not in reasons and "host_gid_range" not in reasons
        ):
            if h_uid < h_gid + length and h_gid < h_uid + length:
                reasons.append("uid_gid_overlap")
        if not isinstance(helpers, dict) or helpers != parent.get("newuidmap"):
            reasons.append("helper_path_mismatch")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        sig = obj.get("sig")
        if not isinstance(sig, str) or not hmac.compare_digest(sig, _expected_sig(obj, key["secret"])):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    if not _is_int(iat):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        elif now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "parent_ns": parent_ns}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "parent_ns": parent_ns}
