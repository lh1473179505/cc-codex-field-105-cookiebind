from __future__ import annotations
from typing import Any

def inspect_subscription(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "subscription": obj.get("subscription"),
        "source": obj.get("source"),
        "event_type": obj.get("event_type"),
        "subject_prefix": obj.get("subject_prefix"),
        "handler": obj.get("handler"),
        "retry": obj.get("retry"),
        "deadletter": obj.get("deadletter"),
        "nonce": obj.get("nonce"),
    }

def admit_subscription(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "subscription": obj.get("subscription")}
