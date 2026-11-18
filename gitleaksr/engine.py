from __future__ import annotations
from typing import Any

def inspect_gitleaks_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rule_id": obj.get("rule_id"),
        "regex": obj.get("regex"),
        "entropy": obj.get("entropy"),
        "keywords": obj.get("keywords"),
        "allowlist": obj.get("allowlist"),
        "secret_group": obj.get("secret_group"),
        "nonce": obj.get("nonce"),
    }

def admit_gitleaks_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "rule_id": obj.get("rule_id")}
