from __future__ import annotations
from typing import Any

def inspect_coa(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "nas_id": obj.get("nas_id"),
        "session_id": obj.get("session_id"),
        "acct_session_id": obj.get("acct_session_id"),
        "username": obj.get("username"),
        "attributes": obj.get("attributes"),
        "source_ip": obj.get("source_ip"),
        "nonce": obj.get("nonce"),
    }

def admit_coa(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "session_id": obj.get("session_id")}
