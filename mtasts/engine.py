from __future__ import annotations
from typing import Any

def inspect_policy(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "policy_id": obj.get("policy_id"),
        "domain": obj.get("domain"),
        "mode": obj.get("mode"),
        "mx": obj.get("mx"),
        "max_age": obj.get("max_age"),
        "report_domain": obj.get("report_domain"),
        "policy_sha256": obj.get("policy_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_policy(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "domain": obj.get("domain")}
