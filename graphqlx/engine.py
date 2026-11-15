from __future__ import annotations
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

def admit_op(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "operation": obj.get("operation")}
