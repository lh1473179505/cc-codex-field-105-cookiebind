from __future__ import annotations
from typing import Any

def inspect_sas(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "account": obj.get("account"),
        "service": obj.get("service"),
        "resource": obj.get("resource"),
        "path": obj.get("path"),
        "permissions": obj.get("permissions"),
        "expiry": obj.get("expiry"),
        "source_ip": obj.get("source_ip"),
        "https": obj.get("https"),
        "nonce": obj.get("nonce"),
    }

def admit_sas(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "account": obj.get("account")}
