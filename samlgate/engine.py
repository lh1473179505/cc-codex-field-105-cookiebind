from __future__ import annotations
from typing import Any

def inspect_assertion(a: dict) -> dict:
    return {"kid": a.get("kid"), "issuer": a.get("issuer"), "audience": a.get("audience"), "recipient": a.get("recipient"), "nonce": a.get("nonce")}

def admit_assertion(a: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "subject": a.get("subject")}
