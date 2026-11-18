from __future__ import annotations
from typing import Any

def inspect_resource(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "tenant": obj.get("tenant"),
        "resource_type": obj.get("resource_type"),
        "external_id": obj.get("external_id"),
        "operation": obj.get("operation"),
        "attributes": obj.get("attributes"),
        "bulk_id": obj.get("bulk_id"),
        "nonce": obj.get("nonce"),
    }

def admit_resource(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "resource_type": obj.get("resource_type")}
