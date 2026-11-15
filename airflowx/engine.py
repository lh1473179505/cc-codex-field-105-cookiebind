from __future__ import annotations
from typing import Any

def inspect_run(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "dag_id": obj.get("dag_id"),
        "owner": obj.get("owner"),
        "pool": obj.get("pool"),
        "queue": obj.get("queue"),
        "nonce": obj.get("nonce"),
    }

def admit_run(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "dag_id": obj.get("dag_id")}
