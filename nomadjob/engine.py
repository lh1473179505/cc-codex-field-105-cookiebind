from __future__ import annotations
from typing import Any

def inspect_job(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "job": obj.get("job"),
        "driver": obj.get("driver"),
        "network": obj.get("network"),
        "volume": obj.get("volume"),
        "image": obj.get("image"),
        "nonce": obj.get("nonce"),
    }

def admit_job(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "job": obj.get("job")}
