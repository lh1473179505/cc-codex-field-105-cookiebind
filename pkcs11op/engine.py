from __future__ import annotations
from typing import Any

def inspect_pkcs11(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "slot": obj.get("slot"),
        "token": obj.get("token"),
        "key_label": obj.get("key_label"),
        "mechanism": obj.get("mechanism"),
        "usage": obj.get("usage"),
        "pin_source": obj.get("pin_source"),
        "nonce": obj.get("nonce"),
    }

def admit_pkcs11(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "key_label": obj.get("key_label")}
