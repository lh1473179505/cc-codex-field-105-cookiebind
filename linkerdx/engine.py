from __future__ import annotations
from typing import Any

def inspect_srv(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "server": obj.get("server"),
        "client": obj.get("client"),
        "port": obj.get("port"),
        "meshtls": obj.get("meshtls"),
        "nonce": obj.get("nonce"),
    }

def admit_srv(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "server": obj.get("server")}
