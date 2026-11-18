from __future__ import annotations
from typing import Any

def inspect_ice_binding(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "session_id": obj.get("session_id"),
        "ufrag": obj.get("ufrag"),
        "dtls_fingerprint": obj.get("dtls_fingerprint"),
        "candidate": obj.get("candidate"),
        "protocol": obj.get("protocol"),
        "nonce": obj.get("nonce"),
    }

def admit_ice_binding(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "session_id": obj.get("session_id")}
