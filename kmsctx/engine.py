from __future__ import annotations
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

def admit_operation(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "key_id": obj.get("key_id")}
