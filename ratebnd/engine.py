from __future__ import annotations
from typing import Any

def inspect_ticket(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "bucket": obj.get("bucket"),
        "subject": obj.get("subject"),
        "cost": obj.get("cost"),
        "window": obj.get("window"),
        "nonce": obj.get("nonce"),
    }

def admit_ticket(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "bucket": obj.get("bucket")}
