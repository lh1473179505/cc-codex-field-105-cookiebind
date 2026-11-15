from __future__ import annotations
from typing import Any

def inspect_image(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "ref": obj.get("ref"),
        "digest": obj.get("digest"),
        "platform": obj.get("platform"),
        "cap_drop": obj.get("cap_drop"),
        "seccomp": obj.get("seccomp"),
        "nonce": obj.get("nonce"),
    }

def admit_image(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "ref": obj.get("ref")}
