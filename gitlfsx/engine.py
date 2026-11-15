from __future__ import annotations
from typing import Any

def inspect_ptr(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "oid": obj.get("oid"),
        "size": obj.get("size"),
        "repo": obj.get("repo"),
        "path": obj.get("path"),
        "nonce": obj.get("nonce"),
    }

def admit_ptr(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "oid": obj.get("oid")}
