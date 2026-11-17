from __future__ import annotations
from typing import Any

def inspect_mapping(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "parent_ns": obj.get("parent_ns"),
        "container_uid": obj.get("container_uid"),
        "container_gid": obj.get("container_gid"),
        "host_uid_start": obj.get("host_uid_start"),
        "host_gid_start": obj.get("host_gid_start"),
        "length": obj.get("length"),
        "newuidmap": obj.get("newuidmap"),
        "nonce": obj.get("nonce"),
    }

def admit_mapping(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "parent_ns": obj.get("parent_ns")}
