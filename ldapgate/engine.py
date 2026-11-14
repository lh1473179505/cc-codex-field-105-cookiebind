from __future__ import annotations
from typing import Any

def inspect_query(query: dict) -> dict:
    return {
        "kid": query.get("kid"),
        "bind_dn": query.get("bind_dn"),
        "base_dn": query.get("base_dn"),
        "filter": query.get("filter"),
        "scope": query.get("scope"),
        "nonce": query.get("nonce"),
    }

def admit_query(query: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "bind_dn": query.get("bind_dn"), "base_dn": query.get("base_dn")}
