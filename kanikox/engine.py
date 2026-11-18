from __future__ import annotations
from typing import Any

def inspect_context(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "context": obj.get("context"),
        "context_sha256": obj.get("context_sha256"),
        "destination": obj.get("destination"),
        "cache": obj.get("cache"),
        "cache_repository": obj.get("cache_repository"),
        "certificate_path": obj.get("certificate_path"),
        "nonce": obj.get("nonce"),
    }

def admit_context(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "context": obj.get("context")}
