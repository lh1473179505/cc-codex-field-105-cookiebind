from __future__ import annotations
from typing import Any

def inspect_dump(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "product": obj.get("product"),
        "build_id": obj.get("build_id"),
        "arch": obj.get("arch"),
        "pc_address": obj.get("pc_address"),
        "module_offset": obj.get("module_offset"),
        "dump_sha256": obj.get("dump_sha256"),
        "size_bytes": obj.get("size_bytes"),
        "nonce": obj.get("nonce"),
    }

def admit_dump(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "product": obj.get("product")}
