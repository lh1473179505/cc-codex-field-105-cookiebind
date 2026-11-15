from __future__ import annotations
from typing import Any

def inspect_unlock(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "lock_id": obj.get("lock_id"),
        "workspace": obj.get("workspace"),
        "backend": obj.get("backend"),
        "who": obj.get("who"),
        "nonce": obj.get("nonce"),
    }

def admit_unlock(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "workspace": obj.get("workspace")}
