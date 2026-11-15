from __future__ import annotations
from typing import Any

def inspect_row(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "tenant": obj.get("tenant"),
        "table": obj.get("table"),
        "op": obj.get("op"),
        "pred": obj.get("pred"),
        "nonce": obj.get("nonce"),
    }

def admit_row(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "tenant": obj.get("tenant")}
