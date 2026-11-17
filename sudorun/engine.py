from __future__ import annotations
from typing import Any

def inspect_command(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "group": obj.get("group"),
        "host": obj.get("host"),
        "command": obj.get("command"),
        "args_sha256": obj.get("args_sha256"),
        "noexec": obj.get("noexec"),
        "nonce": obj.get("nonce"),
    }

def admit_command(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "user": obj.get("user")}
