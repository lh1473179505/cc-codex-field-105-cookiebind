from __future__ import annotations
from typing import Any

def inspect_op(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "cmd": obj.get("cmd"),
        "key": obj.get("key"),
        "channel": obj.get("channel"),
        "arity": obj.get("arity"),
        "nonce": obj.get("nonce"),
    }

def admit_op(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "cmd": obj.get("cmd")}
