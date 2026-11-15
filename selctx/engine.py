from __future__ import annotations
from typing import Any

def inspect_ctx(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "role": obj.get("role"),
        "type": obj.get("type"),
        "range": obj.get("range"),
        "path": obj.get("path"),
        "nonce": obj.get("nonce"),
    }

def admit_ctx(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "type": obj.get("type")}
