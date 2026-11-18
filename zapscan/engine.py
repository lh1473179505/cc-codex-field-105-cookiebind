from __future__ import annotations
from typing import Any

def inspect_zap_policy(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "context": obj.get("context"),
        "target_url": obj.get("target_url"),
        "scan_rule": obj.get("scan_rule"),
        "threshold": obj.get("threshold"),
        "strength": obj.get("strength"),
        "auth": obj.get("auth"),
        "nonce": obj.get("nonce"),
    }

def admit_zap_policy(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "context": obj.get("context")}
