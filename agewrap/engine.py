from __future__ import annotations
from typing import Any

def inspect_box(box: dict) -> dict:
    return {"kid": box.get("kid"), "recipient": box.get("recipient"), "aad": box.get("aad"), "alg": box.get("alg"), "nonce": box.get("nonce")}

def admit_box(box: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "recipient": box.get("recipient")}
