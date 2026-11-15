from __future__ import annotations
from typing import Any

def inspect_job(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "app": obj.get("app"),
        "user": obj.get("user"),
        "master": obj.get("master"),
        "jars": obj.get("jars"),
        "nonce": obj.get("nonce"),
    }

def admit_job(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "app": obj.get("app")}
