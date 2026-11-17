from __future__ import annotations
from typing import Any

def inspect_symbol(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "symbol_server": obj.get("symbol_server"),
        "build_id": obj.get("build_id"),
        "file_name": obj.get("file_name"),
        "arch": obj.get("arch"),
        "file_sha256": obj.get("file_sha256"),
        "path": obj.get("path"),
        "nonce": obj.get("nonce"),
    }

def admit_symbol(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "file_name": obj.get("file_name")}
