from __future__ import annotations
from typing import Any

def inspect_mark(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "mount": obj.get("mount"),
        "path": obj.get("path"),
        "event_mask": obj.get("event_mask"),
        "flags": obj.get("flags"),
        "permission": obj.get("permission"),
        "nonce": obj.get("nonce"),
    }

def admit_mark(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "mount": obj.get("mount")}
