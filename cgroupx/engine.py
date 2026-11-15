from __future__ import annotations
from typing import Any

def inspect_cg(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "path": obj.get("path"),
        "controllers": obj.get("controllers"),
        "memory_max": obj.get("memory_max"),
        "cpu_weight": obj.get("cpu_weight"),
        "nonce": obj.get("nonce"),
    }

def admit_cg(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "path": obj.get("path")}
