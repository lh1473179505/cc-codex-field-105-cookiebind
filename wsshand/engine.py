from __future__ import annotations
from typing import Any

def inspect_handshake(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "origin": obj.get("origin"),
        "host": obj.get("host"),
        "path": obj.get("path"),
        "subprotocol": obj.get("subprotocol"),
        "websocket_key": obj.get("websocket_key"),
        "extensions": obj.get("extensions"),
        "nonce": obj.get("nonce"),
    }

def admit_handshake(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "host": obj.get("host")}
