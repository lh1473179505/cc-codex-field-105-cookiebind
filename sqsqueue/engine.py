from __future__ import annotations
from typing import Any

def inspect_queue_policy(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "queue_arn": obj.get("queue_arn"),
        "account_id": obj.get("account_id"),
        "actions": obj.get("actions"),
        "resource_arn": obj.get("resource_arn"),
        "conditions": obj.get("conditions"),
        "encryption": obj.get("encryption"),
        "nonce": obj.get("nonce"),
    }

def admit_queue_policy(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "queue_arn": obj.get("queue_arn")}
