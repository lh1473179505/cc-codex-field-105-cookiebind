from __future__ import annotations
from typing import Any

def inspect_rr(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "owner": obj.get("owner"),
        "rrtype": obj.get("rrtype"),
        "rdata": obj.get("rdata"),
        "ttl": obj.get("ttl"),
        "nonce": obj.get("nonce"),
    }

def admit_rr(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "owner": obj.get("owner")}
