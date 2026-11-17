from __future__ import annotations
from typing import Any

def inspect_push(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "username": obj.get("username"),
        "common_name": obj.get("common_name"),
        "client_cidr": obj.get("client_cidr"),
        "route_cidr": obj.get("route_cidr"),
        "dns_domains": obj.get("dns_domains"),
        "config_sha256": obj.get("config_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_push(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "username": obj.get("username")}
