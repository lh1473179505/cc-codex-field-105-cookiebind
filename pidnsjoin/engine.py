from __future__ import annotations
from typing import Any

def inspect_join(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "caller": obj.get("caller"),
        "target": obj.get("target"),
        "ns_inode": obj.get("ns_inode"),
        "fd_type": obj.get("fd_type"),
        "capability": obj.get("capability"),
        "nonce": obj.get("nonce"),
    }

def admit_join(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "target": obj.get("target")}
