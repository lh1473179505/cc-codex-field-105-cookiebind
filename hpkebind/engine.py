from __future__ import annotations
from typing import Any

def inspect_encapsulation(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "recipient": obj.get("recipient"),
        "kem": obj.get("kem"),
        "kdf": obj.get("kdf"),
        "aead": obj.get("aead"),
        "info": obj.get("info"),
        "aad": obj.get("aad"),
        "nonce": obj.get("nonce"),
    }

def admit_encapsulation(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "recipient": obj.get("recipient")}
