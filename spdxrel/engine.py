from __future__ import annotations
from typing import Any

def inspect_relationship(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "document_namespace": obj.get("document_namespace"),
        "spdx_id": obj.get("spdx_id"),
        "related_spdx_id": obj.get("related_spdx_id"),
        "relationship_type": obj.get("relationship_type"),
        "license": obj.get("license"),
        "file_sha256": obj.get("file_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_relationship(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "spdx_id": obj.get("spdx_id")}
