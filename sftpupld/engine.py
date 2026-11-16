from __future__ import annotations
from typing import Any

def inspect_upload(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "root": obj.get("root"),
        "path": obj.get("path"),
        "size": obj.get("size"),
        "mode": obj.get("mode"),
        "sha256": obj.get("sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_upload(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "path": obj.get("path")}
