from __future__ import annotations
from typing import Any

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "zone": obj.get("zone"),
        "owner": obj.get("owner"),
        "qname": obj.get("qname"),
        "action": obj.get("action"),
        "cname_target": obj.get("cname_target"),
        "ttl": obj.get("ttl"),
        "rule_sha256": obj.get("rule_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "owner": obj.get("owner")}
