from __future__ import annotations
from typing import Any

def inspect_update(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "zone": obj.get("zone"),
        "owner": obj.get("owner"),
        "rrtype": obj.get("rrtype"),
        "operation": obj.get("operation"),
        "rdata": obj.get("rdata"),
        "ttl": obj.get("ttl"),
        "prerequisites": obj.get("prerequisites"),
        "nonce": obj.get("nonce"),
    }

def admit_update(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "owner": obj.get("owner")}
