from __future__ import annotations
from typing import Any

def inspect_upd(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "map_id": obj.get("map_id"),
        "key_hex": obj.get("key_hex"),
        "value_sha256": obj.get("value_sha256"),
        "pin": obj.get("pin"),
        "nonce": obj.get("nonce"),
    }

def admit_upd(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "map_id": obj.get("map_id")}
