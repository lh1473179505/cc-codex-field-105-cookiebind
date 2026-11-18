from __future__ import annotations
from typing import Any

def inspect_entry(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "log_id": obj.get("log_id"),
        "kind": obj.get("kind"),
        "body_sha256": obj.get("body_sha256"),
        "public_key": obj.get("public_key"),
        "log_index": obj.get("log_index"),
        "integrated_time": obj.get("integrated_time"),
        "nonce": obj.get("nonce"),
    }

def admit_entry(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "log_id": obj.get("log_id")}
