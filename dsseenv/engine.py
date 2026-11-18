from __future__ import annotations
from typing import Any

def inspect_dsse(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "payloadType": obj.get("payloadType"),
        "payload_sha256": obj.get("payload_sha256"),
        "signatures": obj.get("signatures"),
        "threshold": obj.get("threshold"),
        "nonce": obj.get("nonce"),
    }

def admit_dsse(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "payloadType": obj.get("payloadType")}
