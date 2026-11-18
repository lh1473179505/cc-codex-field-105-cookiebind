from __future__ import annotations
from typing import Any

def inspect_device(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "client_id": obj.get("client_id"),
        "device_code_sha256": obj.get("device_code_sha256"),
        "user_code": obj.get("user_code"),
        "interval": obj.get("interval"),
        "expires_in": obj.get("expires_in"),
        "verification_uri": obj.get("verification_uri"),
        "nonce": obj.get("nonce"),
    }

def admit_device(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "client_id": obj.get("client_id")}
