from __future__ import annotations
from typing import Any

def inspect_watch(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "root": obj.get("root"),
        "path": obj.get("path"),
        "event_mask": obj.get("event_mask"),
        "recursive": obj.get("recursive"),
        "max_watches": obj.get("max_watches"),
        "nonce": obj.get("nonce"),
    }

def admit_watch(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "root": obj.get("root")}
