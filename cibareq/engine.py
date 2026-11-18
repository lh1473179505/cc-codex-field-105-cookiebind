from __future__ import annotations
from typing import Any

def inspect_ciba(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "client_id": obj.get("client_id"),
        "login_hint": obj.get("login_hint"),
        "binding_message": obj.get("binding_message"),
        "interval": obj.get("interval"),
        "expires_in": obj.get("expires_in"),
        "scope": obj.get("scope"),
        "nonce": obj.get("nonce"),
    }

def admit_ciba(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "client_id": obj.get("client_id")}
