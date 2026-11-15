from __future__ import annotations
from typing import Any

def inspect_otp(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "public_id": obj.get("public_id"),
        "session": obj.get("session"),
        "use": obj.get("use"),
        "nonce": obj.get("nonce"),
    }

def admit_otp(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "public_id": obj.get("public_id")}
