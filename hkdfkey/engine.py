from __future__ import annotations
from typing import Any

def inspect_derivation(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "purpose": obj.get("purpose"),
        "ikm_sha256": obj.get("ikm_sha256"),
        "salt_hex": obj.get("salt_hex"),
        "info": obj.get("info"),
        "output_length": obj.get("output_length"),
        "algorithm": obj.get("algorithm"),
        "nonce": obj.get("nonce"),
    }

def admit_derivation(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "profile": obj.get("profile")}
