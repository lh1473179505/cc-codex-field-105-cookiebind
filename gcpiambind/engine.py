from __future__ import annotations
from typing import Any

def inspect_binding(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "project": obj.get("project"),
        "role": obj.get("role"),
        "principal": obj.get("principal"),
        "condition": obj.get("condition"),
        "nonce": obj.get("nonce"),
    }

def admit_binding(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "project": obj.get("project")}
