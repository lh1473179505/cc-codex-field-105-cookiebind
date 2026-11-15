from __future__ import annotations
from typing import Any

def inspect_query(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "schema": obj.get("schema"),
        "table": obj.get("table"),
        "op": obj.get("op"),
        "params": obj.get("params"),
        "where_cols": obj.get("where_cols"),
        "nonce": obj.get("nonce"),
    }

def admit_query(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "table": obj.get("table")}
