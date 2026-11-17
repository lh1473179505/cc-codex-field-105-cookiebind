from __future__ import annotations
from typing import Any

def inspect_chain(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "source_role": obj.get("source_role"),
        "target_role": obj.get("target_role"),
        "session_name": obj.get("session_name"),
        "external_id": obj.get("external_id"),
        "duration": obj.get("duration"),
        "mfa": obj.get("mfa"),
        "nonce": obj.get("nonce"),
    }

def admit_chain(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "target_role": obj.get("target_role")}
