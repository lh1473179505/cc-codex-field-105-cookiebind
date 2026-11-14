from __future__ import annotations
from typing import Any

def inspect_token(token: dict) -> dict:
    return {"has_outer": bool(token.get("outer")), "nonce": token.get("nonce")}

def admit_token(token: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sub": None, "aud": None}
