from __future__ import annotations
from typing import Any

def inspect_proposal(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "local_id": obj.get("local_id"),
        "peer_id": obj.get("peer_id"),
        "local_cidr": obj.get("local_cidr"),
        "remote_cidr": obj.get("remote_cidr"),
        "esp": obj.get("esp"),
        "ike": obj.get("ike"),
        "pfs": obj.get("pfs"),
        "lifetime": obj.get("lifetime"),
        "nonce": obj.get("nonce"),
    }

def admit_proposal(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "profile": obj.get("profile")}
