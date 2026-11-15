from __future__ import annotations
from typing import Any

def inspect_pkg(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "purl": obj.get("purl"),
        "registry": obj.get("registry"),
        "name": obj.get("name"),
        "version": obj.get("version"),
        "digest": obj.get("digest"),
        "license": obj.get("license"),
        "nonce": obj.get("nonce"),
    }

def admit_pkg(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "name": obj.get("name")}
