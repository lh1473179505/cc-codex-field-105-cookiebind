from __future__ import annotations
from typing import Any

def inspect_req(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "principal": obj.get("principal"),
        "path": obj.get("path"),
        "method": obj.get("method"),
        "headers": obj.get("headers"),
        "nonce": obj.get("nonce"),
    }

def admit_req(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "path": obj.get("path")}
