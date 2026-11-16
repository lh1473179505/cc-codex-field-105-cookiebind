from __future__ import annotations
from typing import Any

def inspect_ticket(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "realm": obj.get("realm"),
        "spn": obj.get("spn"),
        "enctypes": obj.get("enctypes"),
        "pac": obj.get("pac"),
        "client": obj.get("client"),
        "addresses": obj.get("addresses"),
        "nonce": obj.get("nonce"),
    }

def admit_ticket(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "spn": obj.get("spn")}
