from __future__ import annotations
from typing import Any

def inspect_layout(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "image_ref": obj.get("image_ref"),
        "digest": obj.get("digest"),
        "manifest": obj.get("manifest"),
        "media_type": obj.get("media_type"),
        "platform": obj.get("platform"),
        "nonce": obj.get("nonce"),
    }

def admit_layout(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "image_ref": obj.get("image_ref")}
