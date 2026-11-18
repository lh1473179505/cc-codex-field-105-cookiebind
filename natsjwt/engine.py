from __future__ import annotations
from typing import Any

def inspect_account_jwt(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "issuer": obj.get("issuer"),
        "account": obj.get("account"),
        "signing_key": obj.get("signing_key"),
        "claims": obj.get("claims"),
        "permissions": obj.get("permissions"),
        "expires_in": obj.get("expires_in"),
        "nonce": obj.get("nonce"),
    }

def admit_account_jwt(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "account": obj.get("account")}
