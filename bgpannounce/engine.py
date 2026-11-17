from __future__ import annotations
from typing import Any

def inspect_route(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "peer": obj.get("peer"),
        "as_path": obj.get("as_path"),
        "origin": obj.get("origin"),
        "prefix": obj.get("prefix"),
        "next_hop": obj.get("next_hop"),
        "communities": obj.get("communities"),
        "nonce": obj.get("nonce"),
    }

def admit_route(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "prefix": obj.get("prefix")}
