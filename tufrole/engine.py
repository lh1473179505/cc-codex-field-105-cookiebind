from __future__ import annotations
from typing import Any

def inspect_role(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "repository": obj.get("repository"),
        "role": obj.get("role"),
        "version": obj.get("version"),
        "threshold": obj.get("threshold"),
        "keyids": obj.get("keyids"),
        "nonce": obj.get("nonce"),
    }

def admit_role(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "role": obj.get("role")}
