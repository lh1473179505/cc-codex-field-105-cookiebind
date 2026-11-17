from __future__ import annotations
from typing import Any

def inspect_source(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "hostname": obj.get("hostname"),
        "ip_address": obj.get("ip_address"),
        "stratum": obj.get("stratum"),
        "refid": obj.get("refid"),
        "minpoll": obj.get("minpoll"),
        "maxpoll": obj.get("maxpoll"),
        "auth_key": obj.get("auth_key"),
        "nonce": obj.get("nonce"),
    }

def admit_source(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "hostname": obj.get("hostname")}
