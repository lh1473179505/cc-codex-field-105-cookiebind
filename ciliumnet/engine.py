from __future__ import annotations
from typing import Any

def inspect_pol(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "endpoint": obj.get("endpoint"),
        "direction": obj.get("direction"),
        "cidr": obj.get("cidr"),
        "port": obj.get("port"),
        "proto": obj.get("proto"),
        "nonce": obj.get("nonce"),
    }

def admit_pol(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "endpoint": obj.get("endpoint")}
