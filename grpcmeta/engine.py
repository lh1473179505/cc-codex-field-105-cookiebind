from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_meta(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "authority": obj.get("authority"),
        "method": obj.get("method"),
        "deadline_ms": obj.get("deadline_ms"),
        "peer_cn": obj.get("peer_cn"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{authority}|{method}|{deadline_ms}|{peer_cn}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        authority=obj.get("authority"),
        method=obj.get("method"),
        deadline_ms=obj.get("deadline_ms"),
        peer_cn=obj.get("peer_cn"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def admit_meta(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    authority = obj.get("authority")
    method = obj.get("method")
    peer_cn = obj.get("peer_cn")
    deadline_ms = obj.get("deadline_ms")
    nonce = obj.get("nonce")
    iat = obj.get("iat")
    kid = obj.get("kid")

    if authority not in policy.get("allowed_authorities", []):
        reasons.append("authority_not_allowed")

    if not isinstance(method, str) or any(
        bad in method for bad in policy.get("method_deny_substrings", [])
    ):
        reasons.append("method_denied")
    elif not any(
        method.startswith(p) for p in policy.get("method_allow_prefixes", [])
    ):
        reasons.append("method_prefix_not_allowed")

    if not isinstance(deadline_ms, int) or not (
        policy.get("deadline_min_ms", 0) <= deadline_ms <= policy.get("deadline_max_ms", 0)
    ):
        reasons.append("deadline_out_of_range")

    if not isinstance(peer_cn, str) or not any(
        peer_cn.endswith(s) for s in policy.get("peer_cn_suffixes", [])
    ):
        reasons.append("peer_cn_suffix_not_allowed")
    bind = policy.get("authority_cn_bind", {}).get(authority)
    if bind is None or not isinstance(peer_cn, str) or not peer_cn.endswith(bind):
        reasons.append("peer_cn_authority_bind_mismatch")

    key_entry = keys.get("keys", {}).get(kid)
    if key_entry is None:
        reasons.append("key_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        try:
            secret = bytes.fromhex(key_entry.get("secret", ""))
        except ValueError:
            secret = b""
        expected = base64.urlsafe_b64encode(
            hmac.new(secret, _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_signature")

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    elif iat - now_unix > skew:
        reasons.append("iat_in_future")
    elif now_unix - iat > max_age:
        reasons.append("iat_too_old")

    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "method": method}
    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "method": method}
