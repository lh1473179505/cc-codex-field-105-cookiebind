from __future__ import annotations
from typing import Any

def inspect_repo(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "uri": obj.get("uri"),
        "suite": obj.get("suite"),
        "component": obj.get("component"),
        "signed_by": obj.get("signed_by"),
        "arch": obj.get("arch"),
        "nonce": obj.get("nonce"),
    }

def admit_repo(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "uri": obj.get("uri")}
