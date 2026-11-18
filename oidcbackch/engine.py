from __future__ import annotations
from typing import Any

def inspect_bclogout(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "client_id": obj.get("client_id"),
        "issuer": obj.get("issuer"),
        "aud": obj.get("aud"),
        "sid": obj.get("sid"),
        "events": obj.get("events"),
        "jti_sha256": obj.get("jti_sha256"),
        "delivery": obj.get("delivery"),
        "endpoint": obj.get("endpoint"),
        "session_age": obj.get("session_age"),
        "nonce": obj.get("nonce"),
    }

def admit_bclogout(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "client_id": obj.get("client_id")}
