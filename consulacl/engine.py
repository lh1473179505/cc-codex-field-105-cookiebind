from __future__ import annotations
from typing import Any

def inspect_tok(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "token_id": obj.get("token_id"),
        "ns": obj.get("ns"),
        "rules": obj.get("rules"),
        "service_prefix": obj.get("service_prefix"),
        "node": obj.get("node"),
        "nonce": obj.get("nonce"),
    }

def admit_tok(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "token_id": obj.get("token_id")}
