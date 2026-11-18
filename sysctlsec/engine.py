from __future__ import annotations
from typing import Any

def inspect_setting(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "key": obj.get("key"),
        "value_type": obj.get("value_type"),
        "value": obj.get("value"),
        "namespace": obj.get("namespace"),
        "persistent": obj.get("persistent"),
        "nonce": obj.get("nonce"),
    }

def admit_setting(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "key": obj.get("key")}
