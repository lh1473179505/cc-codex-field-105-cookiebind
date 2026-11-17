from __future__ import annotations
from typing import Any

def inspect_access(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "group": obj.get("group"),
        "share": obj.get("share"),
        "unc_path": obj.get("unc_path"),
        "signing": obj.get("signing"),
        "encryption": obj.get("encryption"),
        "dialect": obj.get("dialect"),
        "nonce": obj.get("nonce"),
    }

def admit_access(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "share": obj.get("share")}
