from __future__ import annotations
from typing import Any

def inspect_update(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "db": obj.get("db"),
        "owner_guid": obj.get("owner_guid"),
        "cert_digest": obj.get("cert_digest"),
        "action": obj.get("action"),
        "append": obj.get("append"),
        "auth": obj.get("auth"),
        "nonce": obj.get("nonce"),
    }

def admit_update(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "db": obj.get("db")}
