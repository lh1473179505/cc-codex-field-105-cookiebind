from __future__ import annotations
from typing import Any

def inspect_bind(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "dn": obj.get("dn"),
        "filter": obj.get("filter"),
        "scope": obj.get("scope"),
        "attrs": obj.get("attrs"),
        "nonce": obj.get("nonce"),
    }

def admit_bind(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "dn": obj.get("dn")}
