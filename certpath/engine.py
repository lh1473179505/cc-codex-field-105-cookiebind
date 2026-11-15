from __future__ import annotations
from typing import Any

def inspect_chain(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "leaf": obj.get("leaf"),
        "chain": obj.get("chain"),
        "eku": obj.get("eku"),
        "dns": obj.get("dns"),
        "nonce": obj.get("nonce"),
    }

def admit_chain(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "leaf": obj.get("leaf")}
