from __future__ import annotations
from typing import Any

def inspect_request(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "cn": obj.get("cn"),
        "dns_names": obj.get("dns_names"),
        "key_alg": obj.get("key_alg"),
        "key_bits": obj.get("key_bits"),
        "key_usage": obj.get("key_usage"),
        "challenge": obj.get("challenge"),
        "nonce": obj.get("nonce"),
    }

def admit_request(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "cn": obj.get("cn")}
