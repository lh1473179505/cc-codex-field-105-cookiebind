from __future__ import annotations
from typing import Any

def inspect_request(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "service": obj.get("service"),
        "region": obj.get("region"),
        "method": obj.get("method"),
        "canonical_path": obj.get("canonical_path"),
        "canonical_query": obj.get("canonical_query"),
        "signed_headers": obj.get("signed_headers"),
        "payload_sha256": obj.get("payload_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_request(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "service": obj.get("service")}
