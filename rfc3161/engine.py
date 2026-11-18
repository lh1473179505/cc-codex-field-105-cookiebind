from __future__ import annotations
from typing import Any

def inspect_timestamp(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "tsa": obj.get("tsa"),
        "digest_alg": obj.get("digest_alg"),
        "message_imprint": obj.get("message_imprint"),
        "request_nonce": obj.get("request_nonce"),
        "cert_req": obj.get("cert_req"),
        "policy_oid": obj.get("policy_oid"),
        "nonce": obj.get("nonce"),
    }

def admit_timestamp(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "tsa": obj.get("tsa")}
