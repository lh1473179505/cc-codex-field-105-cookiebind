from __future__ import annotations
from typing import Any

def inspect_sum(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "module": obj.get("module"),
        "version": obj.get("version"),
        "hash": obj.get("hash"),
        "algo": obj.get("algo"),
        "nonce": obj.get("nonce"),
    }

def admit_sum(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "module": obj.get("module")}
