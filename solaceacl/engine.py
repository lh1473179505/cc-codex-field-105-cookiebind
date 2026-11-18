from __future__ import annotations
from typing import Any

def inspect_publish(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "message_vpn": obj.get("message_vpn"),
        "client": obj.get("client"),
        "exchange": obj.get("exchange"),
        "topic": obj.get("topic"),
        "permission": obj.get("permission"),
        "ttl_seconds": obj.get("ttl_seconds"),
        "nonce": obj.get("nonce"),
    }

def admit_publish(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "topic": obj.get("topic")}
