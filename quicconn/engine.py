from __future__ import annotations
from typing import Any

def inspect_connection(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "sni": obj.get("sni"),
        "alpn": obj.get("alpn"),
        "version": obj.get("version"),
        "transport_params": obj.get("transport_params"),
        "early_data": obj.get("early_data"),
        "nonce": obj.get("nonce"),
    }

def admit_connection(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sni": obj.get("sni")}
