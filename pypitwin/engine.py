from __future__ import annotations
from typing import Any

def inspect_pub(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "project": obj.get("project"),
        "issuer": obj.get("issuer"),
        "sub": obj.get("sub"),
        "claim": obj.get("claim"),
        "nonce": obj.get("nonce"),
    }

def admit_pub(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "project": obj.get("project")}
