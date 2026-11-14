from __future__ import annotations
from typing import Any

def inspect_cert(cert: dict) -> dict:
    return {
        "kid": cert.get("kid"),
        "spiffe_id": cert.get("spiffe_id"),
        "sans": cert.get("sans"),
        "eku": cert.get("eku"),
        "nonce": cert.get("nonce"),
    }

def admit_cert(cert: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "spiffe_id": cert.get("spiffe_id")}
