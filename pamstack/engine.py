from __future__ import annotations
from typing import Any

def inspect_entry(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "service": obj.get("service"),
        "module": obj.get("module"),
        "control": obj.get("control"),
        "arguments": obj.get("arguments"),
        "order": obj.get("order"),
        "nonce": obj.get("nonce"),
    }

def admit_entry(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "service": obj.get("service")}
