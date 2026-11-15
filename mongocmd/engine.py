from __future__ import annotations
from typing import Any

def inspect_op(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "db": obj.get("db"),
        "cmd": obj.get("cmd"),
        "coll": obj.get("coll"),
        "user": obj.get("user"),
        "nonce": obj.get("nonce"),
    }

def admit_op(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "cmd": obj.get("cmd")}
