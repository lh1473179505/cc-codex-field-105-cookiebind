from __future__ import annotations
from typing import Any

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "table": obj.get("table"),
        "chain": obj.get("chain"),
        "iface": obj.get("iface"),
        "set": obj.get("set"),
        "elem": obj.get("elem"),
        "action": obj.get("action"),
        "jump": obj.get("jump"),
        "priority": obj.get("priority"),
        "nonce": obj.get("nonce"),
    }

def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "chain": obj.get("chain")}
