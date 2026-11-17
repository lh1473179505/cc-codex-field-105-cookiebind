from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_NUMERIC_FIELDS = ("offset", "buffer_len", "queue_depth", "timeout_ms", "iat")


def inspect_operation(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "ring_id": obj.get("ring_id"),
        "opcode": obj.get("opcode"),
        "fd_type": obj.get("fd_type"),
        "offset": obj.get("offset"),
        "buffer_len": obj.get("buffer_len"),
        "queue_depth": obj.get("queue_depth"),
        "timeout_ms": obj.get("timeout_ms"),
        "nonce": obj.get("nonce"),
    }

def _is_int(value: Any, forbid_bool: bool) -> bool:
    if forbid_bool and isinstance(value, bool):
        return False
    return isinstance(value, int)

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{ring_id}|{opcode}|{fd_type}|{offset}|{buffer_len}|{queue_depth}|{timeout_ms}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        ring_id=obj.get("ring_id"),
        opcode=obj.get("opcode"),
        fd_type=obj.get("fd_type"),
        offset=obj.get("offset"),
        buffer_len=obj.get("buffer_len"),
        queue_depth=obj.get("queue_depth"),
        timeout_ms=obj.get("timeout_ms"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(obj: dict, secret_hex: str) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        _signing_line(obj).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_operation(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    ring_id = obj.get("ring_id")
    forbid_bool = bool(policy.get("forbid_bool_numbers", True))

    numbers_ok = True
    for field in _NUMERIC_FIELDS:
        if not _is_int(obj.get(field), forbid_bool):
            reasons.append("non_integer_" + field)
            numbers_ok = False

    key = keys.get("keys", {}).get(obj.get("kid"))
    if key is None:
        reasons.append("unknown_key")
    elif key.get("status") != "active":
        reasons.append("key_not_active")
    elif not hmac.compare_digest(_expected_sig(obj, key.get("secret", "")), str(obj.get("sig"))):
        reasons.append("bad_signature")

    if numbers_ok:
        iat = obj["iat"]
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat > now_unix + skew or iat < now_unix - max_age:
            reasons.append("iat_window")

    rings = policy.get("rings", {})
    ring = rings.get(ring_id)
    if ring is None:
        reasons.append("unknown_ring")
    else:
        op = ring.get("ops", {}).get(obj.get("opcode"))
        if op is None:
            reasons.append("unknown_opcode")
        else:
            if obj.get("fd_type") not in op.get("fd_types", []):
                reasons.append("fd_type")
            if numbers_ok:
                offset = obj["offset"]
                buffer_len = obj["buffer_len"]
                if "offset_exact" in op:
                    if offset != op["offset_exact"]:
                        reasons.append("offset_exact")
                elif not (op["offset_min"] <= offset <= op["offset_max"]):
                    reasons.append("offset_range")
                if "buffer_exact" in op:
                    if buffer_len != op["buffer_exact"]:
                        reasons.append("buffer_exact")
                elif not (op["buffer_min"] <= buffer_len <= op["buffer_max"]):
                    reasons.append("buffer_range")
        if numbers_ok:
            if not (ring["queue_depth_min"] <= obj["queue_depth"] <= ring["queue_depth_max"]):
                reasons.append("queue_depth")
            if not (ring["timeout_min"] <= obj["timeout_ms"] <= ring["timeout_max"]):
                reasons.append("timeout")

    nonce = obj.get("nonce")
    if nonce in store.get("items", {}):
        reasons.append("replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "ring_id": ring_id}
    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "ring_id": ring_id}
