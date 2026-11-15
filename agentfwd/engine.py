from __future__ import annotations
from typing import Any

def inspect_fwd(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "fp": obj.get("fp"),
        "dst": obj.get("dst"),
        "constraint": obj.get("constraint"),
        "lifetime": obj.get("lifetime"),
        "nonce": obj.get("nonce"),
    }

def admit_fwd(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "fp": obj.get("fp")}
