from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_bind(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "dn": obj.get("dn"),
        "filter": obj.get("filter"),
        "scope": obj.get("scope"),
        "attrs": obj.get("attrs"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict, attrs_csv: str) -> str:
    return "v1|{kid}|{dn}|{filter}|{scope}|{attrs}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        dn=obj.get("dn"),
        filter=obj.get("filter"),
        scope=obj.get("scope"),
        attrs=attrs_csv,
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_bind(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []

    dn = obj.get("dn")
    if not isinstance(dn, str) or not dn:
        reasons.append("dn_missing")
        dn = dn if isinstance(dn, str) else ""
    else:
        if policy.get("dn_require_lowercase") and dn != dn.lower():
            reasons.append("dn_case")
        if dn not in policy.get("allowed_bases", []):
            reasons.append("dn_base")
        for sub in policy.get("dn_deny_substrings", []):
            if sub in dn:
                reasons.append("dn_deny")
                break

    filt = obj.get("filter")
    if not isinstance(filt, str) or not filt:
        reasons.append("filter_missing")
    else:
        if not any(filt.startswith(p) for p in policy.get("filter_allow_prefixes", [])):
            reasons.append("filter_prefix")
        for sub in policy.get("filter_deny_substrings", []):
            if sub in filt:
                reasons.append("filter_deny")
                break

    scope = obj.get("scope")
    if scope not in policy.get("allowed_scopes", []):
        reasons.append("scope")

    attrs = obj.get("attrs")
    if not isinstance(attrs, list) or not all(isinstance(a, str) for a in attrs):
        reasons.append("attrs_shape")
        attrs = []
    else:
        allow = set(policy.get("attrs_allow", []))
        if any(a not in allow for a in attrs):
            reasons.append("attr")
        if len(attrs) > policy.get("attrs_max", 0):
            reasons.append("attr_max")
    attrs_csv = ",".join(attrs)

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid)
    if key is None:
        reasons.append("kid_unknown")
    else:
        if key.get("status") != "active":
            reasons.append("key_revoked")
        expected = _expected_sig(key.get("secret", ""), _signing_line(obj, attrs_csv))
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_sig")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_missing")
    else:
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("time_stale")
        if iat - now_unix > policy.get("clock_skew_seconds", 0):
            reasons.append("time_future")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_missing")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "dn": dn}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "dn": dn}
