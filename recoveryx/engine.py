from __future__ import annotations
from typing import Any

def inspect_recovery(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user_id": obj.get("user_id"),
        "code_sha256": obj.get("code_sha256"),
        "code_format": obj.get("code_format"),
        "channel": obj.get("channel"),
        "attempt": obj.get("attempt"),
        "used_count": obj.get("used_count"),
        "nonce": obj.get("nonce"),
    }

def admit_recovery(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "user_id": obj.get("user_id")}
