from __future__ import annotations
from typing import Any

def inspect_submission(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "log_id": obj.get("log_id"),
        "chain": obj.get("chain"),
        "root_sha256": obj.get("root_sha256"),
        "not_before": obj.get("not_before"),
        "not_after": obj.get("not_after"),
        "hostname": obj.get("hostname"),
        "nonce": obj.get("nonce"),
    }

def admit_submission(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "log_id": obj.get("log_id")}
