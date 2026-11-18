from __future__ import annotations
from typing import Any

def inspect_stream_reset(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "connection_id": obj.get("connection_id"),
        "stream_id": obj.get("stream_id"),
        "error_code": obj.get("error_code"),
        "stream_state": obj.get("stream_state"),
        "last_stream_id": obj.get("last_stream_id"),
        "flow_control": obj.get("flow_control"),
        "nonce": obj.get("nonce"),
    }

def admit_stream_reset(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "connection_id": obj.get("connection_id")}
