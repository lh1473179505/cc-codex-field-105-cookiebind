from __future__ import annotations
from typing import Any

def inspect_store_path(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "store_path": obj.get("store_path"),
        "nar_hash": obj.get("nar_hash"),
        "size": obj.get("size"),
        "signature": obj.get("signature"),
        "references": obj.get("references"),
        "nonce": obj.get("nonce"),
    }

def admit_store_path(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "store_path": obj.get("store_path")}
