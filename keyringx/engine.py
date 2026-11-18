from __future__ import annotations
from typing import Any

def inspect_operation(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "keyring": obj.get("keyring"),
        "key_type": obj.get("key_type"),
        "payload_length": obj.get("payload_length"),
        "permissions": obj.get("permissions"),
        "timeout": obj.get("timeout"),
        "link": obj.get("link"),
        "nonce": obj.get("nonce"),
    }

def admit_operation(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "keyring": obj.get("keyring")}
