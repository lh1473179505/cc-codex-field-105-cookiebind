from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_OPERATORS = {"=", "!=", "and", "or", "not", "exists", "in", "contains"}

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rule_id": obj.get("rule_id"),
        "priority": obj.get("priority"),
        "condition": obj.get("condition"),
        "output": obj.get("output"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{rule_id}|{priority}|{condition}|{output}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        rule_id=obj.get("rule_id"),
        priority=obj.get("priority"),
        condition=obj.get("condition"),
        output=obj.get("output"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _is_literal_token(token: str) -> bool:
    if token in _OPERATORS:
        return False
    return "." not in token

def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    rule_id = obj.get("rule_id")
    priority = obj.get("priority")
    condition = obj.get("condition") or ""
    output = obj.get("output") or ""
    nonce = obj.get("nonce")
    iat = obj.get("iat")
    kid = obj.get("kid")
    sig = obj.get("sig") or ""

    prefixes = policy.get("rule_id_prefix") or []
    if not isinstance(rule_id, str) or not any(rule_id.startswith(p) for p in prefixes):
        reasons.append("rule_id_prefix")

    if priority not in (policy.get("priorities") or []):
        reasons.append("priority_not_allowed")

    for sub in policy.get("condition_deny_substrings") or []:
        if sub and sub in condition:
            reasons.append("condition_deny_substring")
            break
    allow_tokens = set(policy.get("condition_allow_tokens") or [])
    for token in condition.split():
        if token in allow_tokens or _is_literal_token(token):
            continue
        reasons.append("condition_token_not_allowed")
        break

    output_allow = set(policy.get("output_allow_fields") or [])
    fields = [f.strip() for f in output.split(",") if f.strip()]
    if not fields or any(f not in output_allow for f in fields):
        reasons.append("output_field_not_allowed")

    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("unknown_kid")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        expected = _expected_sig(key_entry["secret"], _signing_line(obj))
        if not hmac.compare_digest(expected, sig):
            reasons.append("bad_signature")

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + skew:
            reasons.append("iat_future")
        if now_unix - iat > max_age:
            reasons.append("iat_expired")

    items = store.setdefault("items", {})
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "rule_id": rule_id}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "rule_id": rule_id}
