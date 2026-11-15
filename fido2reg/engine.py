from __future__ import annotations
from typing import Any

def inspect_cred(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rp_id": obj.get("rp_id"),
        "user_id": obj.get("user_id"),
        "aaguid": obj.get("aaguid"),
        "uv": obj.get("uv"),
        "nonce": obj.get("nonce"),
    }

def admit_cred(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "rp_id": obj.get("rp_id")}
