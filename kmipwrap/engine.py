from __future__ import annotations
from typing import Any

def inspect_wrap(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "key_id": obj.get("key_id"),
        "wrapping_key": obj.get("wrapping_key"),
        "algorithm": obj.get("algorithm"),
        "usage": obj.get("usage"),
        "encoding": obj.get("encoding"),
        "key_bytes": obj.get("key_bytes"),
        "nonce": obj.get("nonce"),
    }

def admit_wrap(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "key_id": obj.get("key_id")}
