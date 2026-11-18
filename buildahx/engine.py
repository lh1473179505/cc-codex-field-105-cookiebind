from __future__ import annotations
from typing import Any

def inspect_build(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "build": obj.get("build"),
        "context": obj.get("context"),
        "base_image": obj.get("base_image"),
        "args": obj.get("args"),
        "secret": obj.get("secret"),
        "isolation": obj.get("isolation"),
        "nonce": obj.get("nonce"),
    }

def admit_build(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "build": obj.get("build")}
