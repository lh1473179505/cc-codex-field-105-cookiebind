from __future__ import annotations
from typing import Any

def inspect_overlay(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "overlay": obj.get("overlay"),
        "base_path": obj.get("base_path"),
        "resources": obj.get("resources"),
        "patches": obj.get("patches"),
        "namespace": obj.get("namespace"),
        "secret_fields": obj.get("secret_fields"),
        "nonce": obj.get("nonce"),
    }

def admit_overlay(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "overlay": obj.get("overlay")}
