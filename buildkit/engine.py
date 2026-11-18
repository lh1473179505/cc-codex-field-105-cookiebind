from __future__ import annotations
from typing import Any

def inspect_secret_mount(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "build": obj.get("build"),
        "target": obj.get("target"),
        "secret_id": obj.get("secret_id"),
        "mount_path": obj.get("mount_path"),
        "mode": obj.get("mode"),
        "uid": obj.get("uid"),
        "gid": obj.get("gid"),
        "required": obj.get("required"),
        "cache_sharing": obj.get("cache_sharing"),
        "cache_key": obj.get("cache_key"),
        "nonce": obj.get("nonce"),
    }

def admit_secret_mount(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "build": obj.get("build")}
