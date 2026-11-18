from __future__ import annotations
from typing import Any

def inspect_cms(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "recipient": obj.get("recipient"),
        "key_alg": obj.get("key_alg"),
        "content_enc": obj.get("content_enc"),
        "aad": obj.get("aad"),
        "digest_alg": obj.get("digest_alg"),
        "nonce": obj.get("nonce"),
    }

def admit_cms(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "recipient": obj.get("recipient")}
