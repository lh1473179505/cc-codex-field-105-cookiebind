from __future__ import annotations
from typing import Any

def inspect_crl(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "issuer": obj.get("issuer"),
        "signature_alg": obj.get("signature_alg"),
        "crl_number": obj.get("crl_number"),
        "this_update": obj.get("this_update"),
        "next_update": obj.get("next_update"),
        "reasons": obj.get("reasons"),
        "nonce": obj.get("nonce"),
    }

def admit_crl(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "issuer": obj.get("issuer")}
