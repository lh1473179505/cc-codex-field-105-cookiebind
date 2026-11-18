from __future__ import annotations
from typing import Any

def inspect_exchange(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "client_id": obj.get("client_id"),
        "subject_type": obj.get("subject_type"),
        "actor_type": obj.get("actor_type"),
        "audience": obj.get("audience"),
        "scope": obj.get("scope"),
        "delegation": obj.get("delegation"),
        "nonce": obj.get("nonce"),
    }

def admit_exchange(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "audience": obj.get("audience")}
