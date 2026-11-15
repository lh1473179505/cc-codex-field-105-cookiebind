from __future__ import annotations
from typing import Any

def inspect_exch(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "client_id": obj.get("client_id"),
        "code_challenge": obj.get("code_challenge"),
        "method": obj.get("method"),
        "redirect": obj.get("redirect"),
        "nonce": obj.get("nonce"),
    }

def admit_exch(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "client_id": obj.get("client_id")}
