from __future__ import annotations
from typing import Any

def inspect_par(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "client_id": obj.get("client_id"),
        "redirect_uri": obj.get("redirect_uri"),
        "code_challenge": obj.get("code_challenge"),
        "code_method": obj.get("code_method"),
        "claims": obj.get("claims"),
        "expires_in": obj.get("expires_in"),
        "nonce": obj.get("nonce"),
    }

def admit_par(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "client_id": obj.get("client_id")}
