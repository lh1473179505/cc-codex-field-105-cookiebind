from __future__ import annotations
from typing import Any

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

def admit_operation(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "ring_id": obj.get("ring_id")}
