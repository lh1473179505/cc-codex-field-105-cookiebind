from __future__ import annotations
from typing import Any

def inspect_pod(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "name": obj.get("name"),
        "ns": obj.get("ns"),
        "privileged": obj.get("privileged"),
        "caps": obj.get("caps"),
        "root_fs": obj.get("root_fs"),
        "nonce": obj.get("nonce"),
    }

def admit_pod(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "name": obj.get("name")}
