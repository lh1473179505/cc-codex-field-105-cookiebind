from __future__ import annotations
from typing import Any

def inspect_mount(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "namespace": obj.get("namespace"),
        "source": obj.get("source"),
        "target": obj.get("target"),
        "fstype": obj.get("fstype"),
        "flags": obj.get("flags"),
        "propagation": obj.get("propagation"),
        "read_only": obj.get("read_only"),
        "nonce": obj.get("nonce"),
    }

def admit_mount(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "target": obj.get("target")}
