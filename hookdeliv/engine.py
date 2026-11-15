from __future__ import annotations
from typing import Any

def inspect_delivery(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "url": obj.get("url"),
        "host": obj.get("host"),
        "method": obj.get("method"),
        "body_sha256": obj.get("body_sha256"),
        "event": obj.get("event"),
        "nonce": obj.get("nonce"),
    }

def admit_delivery(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "event": obj.get("event")}
