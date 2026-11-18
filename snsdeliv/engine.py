from __future__ import annotations
from typing import Any

def inspect_delivery(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "topic_arn": obj.get("topic_arn"),
        "principal": obj.get("principal"),
        "protocol": obj.get("protocol"),
        "endpoint": obj.get("endpoint"),
        "raw_message_delivery": obj.get("raw_message_delivery"),
        "filter_policy": obj.get("filter_policy"),
        "nonce": obj.get("nonce"),
    }

def admit_delivery(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "topic_arn": obj.get("topic_arn")}
