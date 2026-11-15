from __future__ import annotations
from typing import Any

def inspect_hdr(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "host": obj.get("host"),
        "max_age": obj.get("max_age"),
        "include_sub": obj.get("include_sub"),
        "preload": obj.get("preload"),
        "nonce": obj.get("nonce"),
    }

def admit_hdr(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "host": obj.get("host")}
