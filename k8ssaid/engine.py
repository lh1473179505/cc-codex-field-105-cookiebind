from __future__ import annotations
from typing import Any

def inspect_token(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "aud": obj.get("aud"),
        "ns": obj.get("ns"),
        "sa": obj.get("sa"),
        "path": obj.get("path"),
        "bound": obj.get("bound"),
        "nonce": obj.get("nonce"),
    }

def admit_token(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sa": obj.get("sa")}
