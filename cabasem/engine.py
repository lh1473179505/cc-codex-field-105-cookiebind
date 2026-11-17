from __future__ import annotations
from typing import Any

def inspect_certificate(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "not_before": obj.get("not_before"),
        "not_after": obj.get("not_after"),
        "key_alg": obj.get("key_alg"),
        "key_bits": obj.get("key_bits"),
        "san_dns": obj.get("san_dns"),
        "eku": obj.get("eku"),
        "der_sha256": obj.get("der_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_certificate(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "profile": obj.get("profile")}
