from __future__ import annotations
from typing import Any

def inspect_capability(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "path": obj.get("path"),
        "capabilities": obj.get("capabilities"),
        "permitted": obj.get("permitted"),
        "effective": obj.get("effective"),
        "bounding": obj.get("bounding"),
        "nonce": obj.get("nonce"),
    }

def admit_capability(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "path": obj.get("path")}
