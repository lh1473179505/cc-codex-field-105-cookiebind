from __future__ import annotations
from typing import Any

def inspect_mapping(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rule_id": obj.get("rule_id"),
        "technique_id": obj.get("technique_id"),
        "tactic": obj.get("tactic"),
        "data_source": obj.get("data_source"),
        "evidence_fields": obj.get("evidence_fields"),
        "confidence": obj.get("confidence"),
        "nonce": obj.get("nonce"),
    }

def admit_mapping(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "rule_id": obj.get("rule_id")}
