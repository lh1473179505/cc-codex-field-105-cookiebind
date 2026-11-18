from __future__ import annotations
from typing import Any

def inspect_config(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "entry": obj.get("entry"),
        "imports": obj.get("imports"),
        "ext_vars": obj.get("ext_vars"),
        "output_path": obj.get("output_path"),
        "libraries": obj.get("libraries"),
        "nonce": obj.get("nonce"),
    }

def admit_config(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "entry": obj.get("entry")}
