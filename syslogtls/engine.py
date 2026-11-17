from __future__ import annotations
from typing import Any

def inspect_event(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "receiver": obj.get("receiver"),
        "peer_cn": obj.get("peer_cn"),
        "peer_spiffe": obj.get("peer_spiffe"),
        "facility": obj.get("facility"),
        "severity": obj.get("severity"),
        "app": obj.get("app"),
        "message_length": obj.get("message_length"),
        "nonce": obj.get("nonce"),
    }

def admit_event(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "app": obj.get("app")}
