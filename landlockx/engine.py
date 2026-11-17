from __future__ import annotations
from typing import Any

def inspect_ruleset(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "abi": obj.get("abi"),
        "access_fs": obj.get("access_fs"),
        "allowed_path": obj.get("allowed_path"),
        "beneath": obj.get("beneath"),
        "read_write": obj.get("read_write"),
        "nonce": obj.get("nonce"),
    }

def admit_ruleset(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "allowed_path": obj.get("allowed_path")}
