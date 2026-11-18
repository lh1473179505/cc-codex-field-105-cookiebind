from __future__ import annotations
from typing import Any

def inspect_semgrep_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rule_id": obj.get("rule_id"),
        "languages": obj.get("languages"),
        "pattern_form": obj.get("pattern_form"),
        "pattern": obj.get("pattern"),
        "severity": obj.get("severity"),
        "paths_exclude": obj.get("paths_exclude"),
        "nonce": obj.get("nonce"),
    }

def admit_semgrep_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "rule_id": obj.get("rule_id")}
