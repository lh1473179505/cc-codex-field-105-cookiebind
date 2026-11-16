from __future__ import annotations
from typing import Any

def inspect_order(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "account": obj.get("account"),
        "identifiers": obj.get("identifiers"),
        "challenge": obj.get("challenge"),
        "key_auth_sha256": obj.get("key_auth_sha256"),
        "contact": obj.get("contact"),
        "wildcard": obj.get("wildcard"),
        "nonce": obj.get("nonce"),
    }

def admit_order(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "account": obj.get("account")}
