from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_fwd(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "fp": obj.get("fp"),
        "dst": obj.get("dst"),
        "constraint": obj.get("constraint"),
        "lifetime": obj.get("lifetime"),
        "nonce": obj.get("nonce"),
    }

def admit_fwd(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    fp = obj.get("fp")
    dst = obj.get("dst") or ""
    constraint = obj.get("constraint")
    lifetime = obj.get("lifetime")
    iat = obj.get("iat")
    nonce = obj.get("nonce")
    kid = obj.get("kid")

    fps = policy.get("fps", {})
    entry = fps.get(fp)
    if entry is None:
        reasons.append("fp_unknown")
    else:
        if not any(dst.endswith(sfx) for sfx in entry.get("dst_suffixes", [])):
            reasons.append("dst_suffix")
        if constraint not in entry.get("constraints", []):
            reasons.append("constraint")

    if any(bad and bad in dst for bad in policy.get("dst_deny_substrings", [])):
        reasons.append("dst_denied")

    if (
        not isinstance(lifetime, int)
        or isinstance(lifetime, bool)
        or not (policy["lifetime_min"] <= lifetime <= policy["lifetime_max"])
    ):
        reasons.append("lifetime_range")

    key = keys.get("keys", {}).get(kid)
    if key is None:
        reasons.append("kid_unknown")
    else:
        if key.get("status") != "active":
            reasons.append("key_revoked")
        msg = "v1|{}|{}|{}|{}|{}|{}|{}".format(kid, fp, dst, constraint, lifetime, iat, nonce)
        expect = hmac.new(bytes.fromhex(key["secret"]), msg.encode("utf-8"), hashlib.sha256).digest()
        sig = obj.get("sig") or ""
        try:
            got = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        except Exception:
            got = b""
        if not hmac.compare_digest(expect, got):
            reasons.append("bad_signature")

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if not isinstance(iat, int) or isinstance(iat, bool) or iat > now_unix + skew:
        reasons.append("iat_future")
    elif now_unix - iat > max_age:
        reasons.append("iat_expired")

    if not nonce:
        reasons.append("nonce_missing")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "fp": fp}
    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "fp": fp}
