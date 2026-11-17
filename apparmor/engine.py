from __future__ import annotations
from typing import Any

def inspect_profile(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "name": obj.get("name"),
        "path": obj.get("path"),
        "rules": obj.get("rules"),
        "mode": obj.get("mode"),
        "capabilities": obj.get("capabilities"),
        "network": obj.get("network"),
        "nonce": obj.get("nonce"),
    }

def admit_profile(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "name": obj.get("name")}
