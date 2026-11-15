from __future__ import annotations
from typing import Any

def inspect_pol(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "site": obj.get("site"),
        "frame_ancestors": obj.get("frame_ancestors"),
        "sandbox": obj.get("sandbox"),
        "script_mode": obj.get("script_mode"),
        "nonce": obj.get("nonce"),
    }

def admit_pol(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "site": obj.get("site")}
