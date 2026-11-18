from __future__ import annotations
from typing import Any

def inspect_stream_auth(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "channel": obj.get("channel"),
        "last_event_id": obj.get("last_event_id"),
        "origin": obj.get("origin"),
        "event_types": obj.get("event_types"),
        "nonce": obj.get("nonce"),
    }

def admit_stream_auth(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "channel": obj.get("channel")}
