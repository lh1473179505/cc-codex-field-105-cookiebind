from __future__ import annotations
from typing import Any

def inspect_cwe_mapping(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "cve": obj.get("cve"),
        "cwe_id": obj.get("cwe_id"),
        "relation": obj.get("relation"),
        "evidence": obj.get("evidence"),
        "confidence": obj.get("confidence"),
        "nonce": obj.get("nonce"),
    }

def admit_cwe_mapping(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "cve": obj.get("cve")}
