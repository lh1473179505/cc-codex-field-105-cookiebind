from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_pod(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "name": obj.get("name"),
        "ns": obj.get("ns"),
        "privileged": obj.get("privileged"),
        "caps": obj.get("caps"),
        "root_fs": obj.get("root_fs"),
        "nonce": obj.get("nonce"),
    }

def admit_pod(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    name = obj.get("name")
    ns = obj.get("ns")
    privileged = obj.get("privileged")
    caps = obj.get("caps")
    root_fs = obj.get("root_fs")
    nonce = obj.get("nonce")
    iat = obj.get("iat")
    kid = obj.get("kid")
    sig = obj.get("sig")

    cap_list = [c for c in str(caps or "").split(",") if c]

    ns_policy = (policy.get("namespaces") or {}).get(ns)
    if ns_policy is None:
        reasons.append("ns_not_allowed")
    else:
        if not ns_policy.get("allow_privileged", False) and privileged not in (0, "0", False, None):
            reasons.append("privileged_denied")
        allowed = set(ns_policy.get("allowed_caps") or [])
        forbid = set(policy.get("forbid_caps") or [])
        for cap in cap_list:
            if cap in forbid or cap not in allowed:
                reasons.append("cap_not_allowed")
                break
        if ns_policy.get("require_read_only_root", False) and root_fs != "ro":
            reasons.append("rootfs_not_read_only")

    for sub in policy.get("name_deny_substrings") or []:
        if sub and sub in str(name or ""):
            reasons.append("name_denied")
            break

    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("key_unknown")
    else:
        if key_entry.get("status") != "active":
            reasons.append("key_revoked")
        else:
            line = "v1|{}|{}|{}|{}|{}|{}|{}|{}".format(
                kid, name, ns, privileged, caps, root_fs, iat, nonce
            )
            digest = hmac.new(
                bytes.fromhex(key_entry["secret"]), line.encode("utf-8"), hashlib.sha256
            ).digest()
            expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
            if not hmac.compare_digest(expected, str(sig or "")):
                reasons.append("bad_signature")

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + skew:
            reasons.append("iat_in_future")
        elif now_unix - iat > max_age:
            reasons.append("iat_expired")

    items = store.get("items") or {}
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "name": name}
    items[nonce] = {"ts": now_unix}
    store["items"] = items
    return {"decision": "allow", "reason_codes": [], "name": name}
