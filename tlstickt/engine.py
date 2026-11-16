from __future__ import annotations
from typing import Any

def inspect_ticket(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "sni": obj.get("sni"),
        "version": obj.get("version"),
        "cipher": obj.get("cipher"),
        "alpn": obj.get("alpn"),
        "early_data": obj.get("early_data"),
        "max_early": obj.get("max_early"),
        "lifetime": obj.get("lifetime"),
        "nonce": obj.get("nonce"),
    }

def admit_ticket(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sni": obj.get("sni")}
