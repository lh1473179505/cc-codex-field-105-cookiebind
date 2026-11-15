from __future__ import annotations
from typing import Any

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rule_id": obj.get("rule_id"),
        "priority": obj.get("priority"),
        "condition": obj.get("condition"),
        "output": obj.get("output"),
        "nonce": obj.get("nonce"),
    }

def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "rule_id": obj.get("rule_id")}
