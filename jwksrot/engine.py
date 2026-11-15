from __future__ import annotations
from typing import Any

def inspect_keyset(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "kid_new": obj.get("kid_new"),
        "kid_old": obj.get("kid_old"),
        "overlap": obj.get("overlap"),
        "alg": obj.get("alg"),
        "nonce": obj.get("nonce"),
    }

def admit_keyset(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "kid_new": obj.get("kid_new")}
