from __future__ import annotations
from typing import Any

def inspect_req(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "bucket": obj.get("bucket"),
        "key": obj.get("key"),
        "method": obj.get("method"),
        "expires": obj.get("expires"),
        "nonce": obj.get("nonce"),
    }

def admit_req(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "key": obj.get("key")}
