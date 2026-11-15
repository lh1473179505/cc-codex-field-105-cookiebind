from __future__ import annotations
from typing import Any

def inspect_token(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "typ": obj.get("typ"),
        "crit": obj.get("crit"),
        "aud": obj.get("aud"),
        "sub": obj.get("sub"),
        "claim_path": obj.get("claim_path"),
        "claim_val": obj.get("claim_val"),
        "nonce": obj.get("nonce"),
    }

def admit_token(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sub": obj.get("sub")}
