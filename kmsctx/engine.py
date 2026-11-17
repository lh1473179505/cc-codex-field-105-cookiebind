from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_operation(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "key_id": obj.get("key_id"),
        "operation": obj.get("operation"),
        "algorithm": obj.get("algorithm"),
        "context": obj.get("context"),
        "grant": obj.get("grant"),
        "nonce": obj.get("nonce"),
    }

def _context_line(context: dict) -> str:
    return ",".join(f"{k}={context[k]}" for k in sorted(context))

def _signing_line(obj: dict, context: dict) -> str:
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("key_id")),
        str(obj.get("operation")),
        str(obj.get("algorithm")),
        _context_line(context),
        str(obj.get("grant")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def admit_operation(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    key_id = obj.get("key_id")
    reasons: list[str] = []

    def deny(code: str) -> dict:
        return {"decision": "deny", "reason_codes": [code], "key_id": key_id}

    key_policy = (policy.get("keys") or {}).get(key_id)
    if key_policy is None:
        return deny("unknown_key")

    op_policy = (key_policy.get("operations") or {}).get(obj.get("operation"))
    if op_policy is None:
        return deny("unknown_operation")

    if obj.get("algorithm") not in (op_policy.get("algorithms") or []):
        return deny("unknown_algorithm")

    if obj.get("grant") not in (op_policy.get("grants") or []):
        return deny("unknown_grant")

    context = obj.get("context")
    if not isinstance(context, dict):
        return deny("context_required")

    allowed = set(key_policy.get("context_allowed") or [])
    forbidden = set(key_policy.get("context_forbidden") or [])
    required = key_policy.get("context_required") or {}

    for req_key, req_value in required.items():
        if req_key not in context:
            return deny("context_required")
        if context[req_key] != req_value:
            return deny("context_value")
    for ctx_key in context:
        if ctx_key in forbidden:
            return deny("context_forbidden")
        if ctx_key not in allowed:
            return deny("context_not_allowed")

    request_id = context.get("request_id")
    if request_id is not None:
        pattern = policy.get("request_id_pattern")
        if pattern and not re.fullmatch(pattern, str(request_id)):
            return deny("request_id")

    kid = obj.get("kid")
    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        return deny("unknown_kid")

    line = _signing_line(obj, context)
    expected = _expected_sig(key_entry["secret"], line)
    if not hmac.compare_digest(expected, str(obj.get("sig"))):
        return deny("bad_signature")

    if key_entry.get("status") != "active":
        return deny("key_revoked")

    try:
        iat = int(obj.get("iat"))
    except (TypeError, ValueError):
        return deny("bad_iat")
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if iat > now_unix + skew:
        return deny("iat_in_future")
    if now_unix - iat > max_age:
        return deny("iat_expired")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        return deny("replay")

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": reasons, "key_id": key_id}
