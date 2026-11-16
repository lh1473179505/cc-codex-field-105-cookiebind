from __future__ import annotations
from typing import Any

def inspect_trap(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "engine_id": obj.get("engine_id"),
        "user": obj.get("user"),
        "auth": obj.get("auth"),
        "priv": obj.get("priv"),
        "oid": obj.get("oid"),
        "varbinds": obj.get("varbinds"),
        "severity": obj.get("severity"),
        "nonce": obj.get("nonce"),
    }

def admit_trap(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "oid": obj.get("oid")}
