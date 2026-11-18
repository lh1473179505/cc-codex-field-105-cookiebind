from __future__ import annotations
from typing import Any

def inspect_target_file(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "repository": obj.get("repository"),
        "target_path": obj.get("target_path"),
        "length": obj.get("length"),
        "hashes": obj.get("hashes"),
        "role": obj.get("role"),
        "delegation": obj.get("delegation"),
        "nonce": obj.get("nonce"),
    }

def admit_target_file(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "target_path": obj.get("target_path")}
