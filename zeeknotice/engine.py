from __future__ import annotations
from typing import Any

def inspect_notice(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "notice_type": obj.get("notice_type"),
        "source_script": obj.get("source_script"),
        "severity": obj.get("severity"),
        "action": obj.get("action"),
        "field_names": obj.get("field_names"),
        "nonce": obj.get("nonce"),
    }

def admit_notice(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "notice_type": obj.get("notice_type")}
