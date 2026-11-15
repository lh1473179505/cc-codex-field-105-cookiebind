from __future__ import annotations
from typing import Any

def inspect_art(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "group": obj.get("group"),
        "artifact": obj.get("artifact"),
        "version": obj.get("version"),
        "fp": obj.get("fp"),
        "nonce": obj.get("nonce"),
    }

def admit_art(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "artifact": obj.get("artifact")}
