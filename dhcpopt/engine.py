from __future__ import annotations
from typing import Any

def inspect_option(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "subnet": obj.get("subnet"),
        "option_code": obj.get("option_code"),
        "value_type": obj.get("value_type"),
        "value": obj.get("value"),
        "pool_start": obj.get("pool_start"),
        "pool_end": obj.get("pool_end"),
        "nonce": obj.get("nonce"),
    }

def admit_option(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "subnet": obj.get("subnet")}
