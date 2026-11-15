from __future__ import annotations
from typing import Any

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "principal": obj.get("principal"),
        "ns": obj.get("ns"),
        "path": obj.get("path"),
        "method": obj.get("method"),
        "nonce": obj.get("nonce"),
    }

def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "principal": obj.get("principal")}
