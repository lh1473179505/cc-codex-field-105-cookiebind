from __future__ import annotations
from typing import Any

def inspect_caps(caps: dict) -> dict:
    return {
        "kid": caps.get("kid"),
        "permitted": list(caps.get("permitted") or []),
        "effective": list(caps.get("effective") or []),
        "bounding": list(caps.get("bounding") or []),
        "ambient": list(caps.get("ambient") or []),
        "no_new_privs": caps.get("no_new_privs"),
        "securebits": caps.get("securebits"),
    }

def admit_caps(caps: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "effective": [], "ambient": []}
