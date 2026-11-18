from __future__ import annotations
from typing import Any

def inspect_xml(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "recipient": obj.get("recipient"),
        "key_transport": obj.get("key_transport"),
        "data_alg": obj.get("data_alg"),
        "key_size": obj.get("key_size"),
        "reference_uri": obj.get("reference_uri"),
        "nonce": obj.get("nonce"),
    }

def admit_xml(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "recipient": obj.get("recipient")}
