from __future__ import annotations
from typing import Any

def inspect_jail(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "name": obj.get("name"),
        "jid": obj.get("jid"),
        "hostname": obj.get("hostname"),
        "ip4": obj.get("ip4"),
        "path": obj.get("path"),
        "securelevel": obj.get("securelevel"),
        "nonce": obj.get("nonce"),
    }

def admit_jail(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "name": obj.get("name")}
