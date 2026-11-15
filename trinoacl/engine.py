from __future__ import annotations
from typing import Any

def inspect_q(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "catalog": obj.get("catalog"),
        "schema": obj.get("schema"),
        "table": obj.get("table"),
        "user": obj.get("user"),
        "nonce": obj.get("nonce"),
    }

def admit_q(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "catalog": obj.get("catalog")}
