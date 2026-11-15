from __future__ import annotations
from typing import Any

def inspect_sig(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "sid": obj.get("sid"),
        "proto": obj.get("proto"),
        "msg": obj.get("msg"),
        "content": obj.get("content"),
        "nonce": obj.get("nonce"),
    }

def admit_sig(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sid": obj.get("sid")}
