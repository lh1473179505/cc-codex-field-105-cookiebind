from __future__ import annotations
from typing import Any

def inspect_binding(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "peer": obj.get("peer"),
        "lsr_id": obj.get("lsr_id"),
        "fec": obj.get("fec"),
        "transport_address": obj.get("transport_address"),
        "label": obj.get("label"),
        "binding_sha256": obj.get("binding_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_binding(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "fec": obj.get("fec")}
