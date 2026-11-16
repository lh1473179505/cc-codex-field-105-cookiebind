from __future__ import annotations
from typing import Any

def inspect_exch(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "client_id": obj.get("client_id"),
        "code": obj.get("code"),
        "challenge": obj.get("challenge"),
        "method": obj.get("method"),
        "redirect": obj.get("redirect"),
        "jkt": obj.get("jkt"),
        "nonce": obj.get("nonce"),
    }

def admit_exch(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "client_id": obj.get("client_id")}
