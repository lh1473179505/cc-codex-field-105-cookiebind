from __future__ import annotations
from typing import Any

def inspect_core(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "process": obj.get("process"),
        "core_path": obj.get("core_path"),
        "size_bytes": obj.get("size_bytes"),
        "compression": obj.get("compression"),
        "owner": obj.get("owner"),
        "sensitive": obj.get("sensitive"),
        "nonce": obj.get("nonce"),
    }

def admit_core(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "process": obj.get("process")}
