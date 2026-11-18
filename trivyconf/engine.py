from __future__ import annotations
from typing import Any

def inspect_trivy_config(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "target": obj.get("target"),
        "scanners": obj.get("scanners"),
        "severities": obj.get("severities"),
        "ignore_rules": obj.get("ignore_rules"),
        "offline_db": obj.get("offline_db"),
        "nonce": obj.get("nonce"),
    }

def admit_trivy_config(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "target": obj.get("target")}
