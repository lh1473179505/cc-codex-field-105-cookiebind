from __future__ import annotations
from typing import Any

def inspect_artifact(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "artifact_id": obj.get("artifact_id"),
        "public_key": obj.get("public_key"),
        "signature": obj.get("signature"),
        "canonical_digest": obj.get("canonical_digest"),
        "artifact_size": obj.get("artifact_size"),
        "trusted_comment": obj.get("trusted_comment"),
        "nonce": obj.get("nonce"),
    }

def admit_artifact(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "artifact_id": obj.get("artifact_id")}
