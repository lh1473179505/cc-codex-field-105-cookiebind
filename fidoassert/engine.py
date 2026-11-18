from __future__ import annotations
from typing import Any

def inspect_assertion(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rp_id": obj.get("rp_id"),
        "credential_id": obj.get("credential_id"),
        "up": obj.get("up"),
        "uv": obj.get("uv"),
        "sign_count": obj.get("sign_count"),
        "challenge_sha256": obj.get("challenge_sha256"),
        "origin": obj.get("origin"),
        "nonce": obj.get("nonce"),
    }

def admit_assertion(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "credential_id": obj.get("credential_id")}
