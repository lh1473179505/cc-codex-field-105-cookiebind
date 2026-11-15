from __future__ import annotations
from typing import Any

def inspect_sig(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "key_fp": obj.get("key_fp"),
        "algo": obj.get("algo"),
        "hash": obj.get("hash"),
        "body_sha256": obj.get("body_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_sig(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "key_fp": obj.get("key_fp")}
