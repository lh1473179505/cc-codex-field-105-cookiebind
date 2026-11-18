from __future__ import annotations
from typing import Any

def inspect_acl(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "path": obj.get("path"),
        "entry_type": obj.get("entry_type"),
        "principal": obj.get("principal"),
        "permissions": obj.get("permissions"),
        "mask": obj.get("mask"),
        "default": obj.get("default"),
        "recursive": obj.get("recursive"),
        "nonce": obj.get("nonce"),
    }

def admit_acl(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "path": obj.get("path")}
