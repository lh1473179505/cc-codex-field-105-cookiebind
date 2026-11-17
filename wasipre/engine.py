from __future__ import annotations
from typing import Any

def inspect_capability(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "module": obj.get("module"),
        "path": obj.get("path"),
        "preopen": obj.get("preopen"),
        "read": obj.get("read"),
        "write": obj.get("write"),
        "nonce": obj.get("nonce"),
    }

def admit_capability(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "module": obj.get("module")}
