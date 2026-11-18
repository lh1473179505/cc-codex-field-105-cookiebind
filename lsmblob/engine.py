from __future__ import annotations
from typing import Any

def inspect_blob(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "object": obj.get("object"),
        "label": obj.get("label"),
        "blob_fields": obj.get("blob_fields"),
        "operator": obj.get("operator"),
        "context": obj.get("context"),
        "nonce": obj.get("nonce"),
    }

def admit_blob(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "object": obj.get("object")}
