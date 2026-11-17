from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_chain(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "source_role": obj.get("source_role"),
        "target_role": obj.get("target_role"),
        "session_name": obj.get("session_name"),
        "external_id": obj.get("external_id"),
        "duration": obj.get("duration"),
        "mfa": obj.get("mfa"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    fields = (
        "kid", "source_role", "target_role", "session_name",
        "external_id", "duration", "mfa", "iat", "nonce",
    )
    return "v1|" + "|".join(str(obj.get(f, "")) for f in fields)

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_chain(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    target_role = obj.get("target_role")

    source_role = obj.get("source_role")
    sources = policy.get("sources", {})
    source = sources.get(source_role)
    edge = None
    if source is None:
        reasons.append("unknown_source")
    else:
        edge = source.get("targets", {}).get(target_role)
        if edge is None:
            reasons.append("unknown_target")

    if edge is not None:
        if obj.get("external_id") != edge.get("external_id"):
            reasons.append("external_id_mismatch")
        duration = obj.get("duration")
        if not isinstance(duration, int) or isinstance(duration, bool) or not (
            edge.get("duration_min", 0) <= duration <= edge.get("duration_max", 0)
        ):
            reasons.append("duration_out_of_range")
        session_name = obj.get("session_name")
        if not isinstance(session_name, str) or not re.fullmatch(policy.get("session_pattern", ".*"), session_name):
            reasons.append("session_syntax")
        elif not any(session_name.startswith(p) for p in edge.get("session_prefixes", [])):
            reasons.append("session_prefix")
        mfa = obj.get("mfa")
        if edge.get("mfa_required"):
            if not mfa:
                reasons.append("mfa_required")
            elif not isinstance(mfa, str) or not re.fullmatch(policy.get("mfa_pattern", ".*"), mfa):
                reasons.append("mfa_format")
            elif not mfa.startswith(edge.get("mfa_prefix", "")):
                reasons.append("mfa_prefix")
        else:
            if mfa != "":
                reasons.append("mfa_unexpected")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid)
    if key is None:
        reasons.append("unknown_key")
    else:
        if key.get("status") != "active":
            reasons.append("key_not_active")
        expected = _expected_sig(key.get("secret", ""), _signing_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig", ""))):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_invalid")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat > now_unix + skew:
            reasons.append("iat_future")
        elif now_unix - iat > max_age:
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "target_role": target_role}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "target_role": target_role}
