from __future__ import annotations
from typing import Any

def inspect_negotiation(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "service": obj.get("service"),
        "spn": obj.get("spn"),
        "realm": obj.get("realm"),
        "mech_types": obj.get("mech_types"),
        "mutual": obj.get("mutual"),
        "address": obj.get("address"),
        "nonce": obj.get("nonce"),
    }

def admit_negotiation(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "spn": obj.get("spn")}
