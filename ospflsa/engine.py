from __future__ import annotations
from typing import Any

def inspect_lsa(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "area": obj.get("area"),
        "router_id": obj.get("router_id"),
        "lsa_type": obj.get("lsa_type"),
        "lsid": obj.get("lsid"),
        "age": obj.get("age"),
        "sequence": obj.get("sequence"),
        "payload_sha256": obj.get("payload_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_lsa(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "lsid": obj.get("lsid")}
