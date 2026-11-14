from __future__ import annotations
from typing import Any

def inspect_idtoken(tok: dict) -> dict:
    return {"kid": tok.get("kid"), "iss": tok.get("iss"), "aud": tok.get("aud"), "azp": tok.get("azp"), "nonce": tok.get("nonce"), "acr": tok.get("acr")}

def admit_idtoken(tok: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sub": tok.get("sub")}
