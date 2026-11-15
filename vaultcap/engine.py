from __future__ import annotations
from typing import Any

def inspect_tok(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "ns": obj.get("ns"),
        "path": obj.get("path"),
        "caps": obj.get("caps"),
        "wrap_ttl": obj.get("wrap_ttl"),
        "nonce": obj.get("nonce"),
    }

def admit_tok(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "path": obj.get("path")}
