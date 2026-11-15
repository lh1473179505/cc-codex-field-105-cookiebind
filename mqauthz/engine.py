from __future__ import annotations
from typing import Any

def inspect_pub(pub: dict) -> dict:
    return {
        "kid": pub.get("kid"),
        "client_id": pub.get("client_id"),
        "cn": pub.get("cn"),
        "topic": pub.get("topic"),
        "qos": pub.get("qos"),
        "retain": pub.get("retain"),
        "nonce": pub.get("nonce"),
    }

def admit_pub(pub: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "topic": pub.get("topic")}
