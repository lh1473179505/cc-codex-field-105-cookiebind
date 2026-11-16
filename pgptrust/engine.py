from __future__ import annotations
from typing import Any

def inspect_sig(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "key_fp": obj.get("key_fp"),
        "signer_fp": obj.get("signer_fp"),
        "depth": obj.get("depth"),
        "algo": obj.get("algo"),
        "hash": obj.get("hash"),
        "notation": obj.get("notation"),
        "nonce": obj.get("nonce"),
    }

def admit_sig(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "key_fp": obj.get("key_fp")}
