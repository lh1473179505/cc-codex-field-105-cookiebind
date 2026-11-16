from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_op(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "operation": obj.get("operation"),
        "depth": obj.get("depth"),
        "complexity": obj.get("complexity"),
        "fields": obj.get("fields"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("operation")),
        str(obj.get("depth")),
        str(obj.get("complexity")),
        str(obj.get("fields")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)

def admit_op(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []

    def deny(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    operation = obj.get("operation")
    operations = policy.get("operations", {})
    op_policy = operations.get(operation) if isinstance(operations, dict) else None
    if not isinstance(op_policy, dict):
        deny("unknown_operation")

    depth = obj.get("depth")
    complexity = obj.get("complexity")
    fields_raw = obj.get("fields")
    if op_policy is not None:
        if not _is_int(depth) or depth > op_policy.get("depth_max"):
            deny("depth_exceeded")
        if not _is_int(complexity) or complexity > op_policy.get("complexity_max"):
            deny("complexity_exceeded")

        field_allow = op_policy.get("field_allow", [])
        forbid_fields = policy.get("forbid_fields", [])
        if not isinstance(fields_raw, str):
            deny("malformed_fields")
            fields: list[str] = []
        else:
            fields = [part.strip() for part in fields_raw.split(",")]
        for field in fields:
            if field in forbid_fields:
                deny("forbidden_field")
            elif field not in field_allow:
                deny("field_not_allowed")

    kid = obj.get("kid")
    key_entries = keys.get("keys", {})
    key = key_entries.get(kid) if isinstance(key_entries, dict) else None
    if not isinstance(key, dict):
        deny("unknown_kid")
    else:
        if key.get("status") != "active":
            deny("key_revoked")
        try:
            secret = bytes.fromhex(key.get("secret", ""))
        except (TypeError, ValueError):
            secret = b""
            deny("bad_signature")
        expected = _b64url(
            hmac.new(secret, _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
        )
        sig = obj.get("sig")
        if not isinstance(sig, str) or not hmac.compare_digest(expected, sig):
            deny("bad_signature")

    iat = obj.get("iat")
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if not _is_int(iat) or not (now_unix - max_age - skew <= iat <= now_unix + skew):
        deny("iat_out_of_window")

    nonce = obj.get("nonce")
    items = store.get("items")
    if not isinstance(nonce, str) or not nonce:
        deny("missing_nonce")
    elif isinstance(items, dict) and nonce in items:
        deny("nonce_replayed")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "operation": operation}

    if isinstance(items, dict):
        items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "operation": operation}
