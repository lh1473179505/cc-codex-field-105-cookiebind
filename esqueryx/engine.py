from __future__ import annotations
from typing import Any

def inspect_q(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "index": obj.get("index"),
        "user": obj.get("user"),
        "qtype": obj.get("qtype"),
        "fields": obj.get("fields"),
        "nonce": obj.get("nonce"),
    }

def admit_q(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "index": obj.get("index")}
