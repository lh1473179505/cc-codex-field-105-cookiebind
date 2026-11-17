from __future__ import annotations
from typing import Any

def inspect_query(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "pack": obj.get("pack"),
        "query_name": obj.get("query_name"),
        "sql": obj.get("sql"),
        "tables": obj.get("tables"),
        "interval": obj.get("interval"),
        "platform": obj.get("platform"),
        "nonce": obj.get("nonce"),
    }

def admit_query(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "query_name": obj.get("query_name")}
