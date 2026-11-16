from __future__ import annotations
from typing import Any

def inspect_result(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "tool": obj.get("tool"),
        "rule_id": obj.get("rule_id"),
        "level": obj.get("level"),
        "uri": obj.get("uri"),
        "start_line": obj.get("start_line"),
        "end_line": obj.get("end_line"),
        "fingerprints": obj.get("fingerprints"),
        "nonce": obj.get("nonce"),
    }

def admit_result(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "rule_id": obj.get("rule_id")}
