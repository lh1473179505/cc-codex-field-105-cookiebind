from __future__ import annotations
from typing import Any

def inspect_request(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "resource": obj.get("resource"),
        "role": obj.get("role"),
        "duration": obj.get("duration"),
        "ticket": obj.get("ticket"),
        "approval": obj.get("approval"),
        "nonce": obj.get("nonce"),
    }

def admit_request(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "resource": obj.get("resource")}
