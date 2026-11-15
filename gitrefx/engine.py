from __future__ import annotations
from typing import Any

def inspect_update(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "ref": obj.get("ref"),
        "old_oid": obj.get("old_oid"),
        "new_oid": obj.get("new_oid"),
        "actor": obj.get("actor"),
        "force": obj.get("force"),
        "nonce": obj.get("nonce"),
    }

def admit_update(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "ref": obj.get("ref")}
