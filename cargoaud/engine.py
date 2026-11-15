from __future__ import annotations
from typing import Any

def inspect_crate(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "name": obj.get("name"),
        "version": obj.get("version"),
        "advisory": obj.get("advisory"),
        "severity": obj.get("severity"),
        "nonce": obj.get("nonce"),
    }

def admit_crate(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "name": obj.get("name")}
