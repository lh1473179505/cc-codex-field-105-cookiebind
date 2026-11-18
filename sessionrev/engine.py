from __future__ import annotations
from typing import Any

def inspect_revocation(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user_id": obj.get("user_id"),
        "client_id": obj.get("client_id"),
        "sid": obj.get("sid"),
        "reason": obj.get("reason"),
        "effective_in": obj.get("effective_in"),
        "device_id": obj.get("device_id"),
        "nonce": obj.get("nonce"),
    }

def admit_revocation(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sid": obj.get("sid")}
