from __future__ import annotations
from typing import Any

def inspect_trace(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "caller": obj.get("caller"),
        "target": obj.get("target"),
        "scope": obj.get("scope"),
        "capability": obj.get("capability"),
        "dumpable": obj.get("dumpable"),
        "yama": obj.get("yama"),
        "nonce": obj.get("nonce"),
    }

def admit_trace(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "target": obj.get("target")}
