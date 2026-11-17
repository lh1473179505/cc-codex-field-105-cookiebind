from __future__ import annotations
from typing import Any

def inspect_action(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "subject": obj.get("subject"),
        "action": obj.get("action"),
        "auth": obj.get("auth"),
        "annotations": obj.get("annotations"),
        "session": obj.get("session"),
        "nonce": obj.get("nonce"),
    }

def admit_action(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "action": obj.get("action")}
