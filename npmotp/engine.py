from __future__ import annotations
from typing import Any

def inspect_pub(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "pkg": obj.get("pkg"),
        "otp": obj.get("otp"),
        "user": obj.get("user"),
        "registry": obj.get("registry"),
        "nonce": obj.get("nonce"),
    }

def admit_pub(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "pkg": obj.get("pkg")}
