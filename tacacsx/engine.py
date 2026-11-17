from __future__ import annotations
from typing import Any

def inspect_command(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "group": obj.get("group"),
        "service": obj.get("service"),
        "command": obj.get("command"),
        "args": obj.get("args"),
        "priv_lvl": obj.get("priv_lvl"),
        "nonce": obj.get("nonce"),
    }

def admit_command(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "command": obj.get("command")}
