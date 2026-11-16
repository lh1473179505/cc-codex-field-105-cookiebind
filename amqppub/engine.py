from __future__ import annotations
from typing import Any

def inspect_message(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "vhost": obj.get("vhost"),
        "exchange": obj.get("exchange"),
        "routing_key": obj.get("routing_key"),
        "delivery_mode": obj.get("delivery_mode"),
        "headers": obj.get("headers"),
        "body_sha256": obj.get("body_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_message(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "routing_key": obj.get("routing_key")}
