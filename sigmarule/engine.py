from __future__ import annotations
from typing import Any

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rule_id": obj.get("rule_id"),
        "title": obj.get("title"),
        "logsource": obj.get("logsource"),
        "detection": obj.get("detection"),
        "level": obj.get("level"),
        "field_names": obj.get("field_names"),
        "nonce": obj.get("nonce"),
    }

def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "rule_id": obj.get("rule_id")}
