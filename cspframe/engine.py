from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_pol(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "site": obj.get("site"),
        "frame_ancestors": obj.get("frame_ancestors"),
        "sandbox": obj.get("sandbox"),
        "script_mode": obj.get("script_mode"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{site}|{frame_ancestors}|{sandbox}|{script_mode}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        site=obj.get("site"),
        frame_ancestors=obj.get("frame_ancestors"),
        sandbox=obj.get("sandbox"),
        script_mode=obj.get("script_mode"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_pol(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []
    site = obj.get("site")

    site_policy = (policy.get("sites") or {}).get(site)
    if site_policy is None:
        codes.append("site_not_allowed")

    if policy.get("forbid_star_ancestor") and "*" in str(obj.get("frame_ancestors") or "").split():
        codes.append("star_ancestor_forbidden")
    if site_policy is not None:
        allow = set(site_policy.get("ancestors_allow") or [])
        tokens = str(obj.get("frame_ancestors") or "").split()
        if not tokens or any(t not in allow for t in tokens):
            codes.append("ancestor_not_allowed")
        if site_policy.get("sandbox_required") and obj.get("sandbox") != 1:
            codes.append("sandbox_required")
        script_mode = obj.get("script_mode")
        if script_mode not in (site_policy.get("script_modes") or []):
            codes.append("script_mode_not_allowed")

    if policy.get("forbid_unsafe_inline_script") and obj.get("script_mode") == "unsafe-inline":
        codes.append("unsafe_inline_forbidden")

    key_entry = (keys.get("keys") or {}).get(obj.get("kid"))
    if key_entry is None:
        codes.append("unknown_kid")
    elif key_entry.get("status") != "active":
        codes.append("key_revoked")
    else:
        expected = _expected_sig(key_entry.get("secret", ""), _signing_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig") or "")):
            codes.append("bad_signature")

    try:
        iat = int(obj.get("iat"))
    except (TypeError, ValueError):
        codes.append("iat_invalid")
    else:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat - now_unix > skew:
            codes.append("iat_future")
        if now_unix - iat > max_age:
            codes.append("iat_expired")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if not nonce or nonce in items:
        codes.append("nonce_replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "site": site}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "site": site}
