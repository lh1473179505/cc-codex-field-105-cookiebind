from __future__ import annotations
from typing import Any

def inspect_kev_binding(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "cve": obj.get("cve"),
        "product": obj.get("product"),
        "due_date": obj.get("due_date"),
        "priority": obj.get("priority"),
        "owner": obj.get("owner"),
        "action": obj.get("action"),
        "nonce": obj.get("nonce"),
    }

def admit_kev_binding(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "cve": obj.get("cve")}
