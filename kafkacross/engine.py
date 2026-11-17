from __future__ import annotations
from typing import Any

def inspect_acl(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "principal": obj.get("principal"),
        "resource": obj.get("resource"),
        "name": obj.get("name"),
        "op": obj.get("op"),
        "group": obj.get("group"),
        "client": obj.get("client"),
        "host": obj.get("host"),
        "pattern": obj.get("pattern"),
        "nonce": obj.get("nonce"),
    }

def admit_acl(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "principal": obj.get("principal")}
