from __future__ import annotations
from typing import Any

def inspect_keylog(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "session_id": obj.get("session_id"),
        "label": obj.get("label"),
        "client_random": obj.get("client_random"),
        "secret_length": obj.get("secret_length"),
        "purpose": obj.get("purpose"),
        "retention_seconds": obj.get("retention_seconds"),
        "nonce": obj.get("nonce"),
    }

def admit_keylog(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "session_id": obj.get("session_id")}
