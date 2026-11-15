from __future__ import annotations
from typing import Any

def inspect_meta(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "authority": obj.get("authority"),
        "method": obj.get("method"),
        "deadline_ms": obj.get("deadline_ms"),
        "peer_cn": obj.get("peer_cn"),
        "nonce": obj.get("nonce"),
    }

def admit_meta(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "method": obj.get("method")}
