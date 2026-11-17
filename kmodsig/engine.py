from __future__ import annotations
from typing import Any

def inspect_module(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "module": obj.get("module"),
        "path": obj.get("path"),
        "digest": obj.get("digest"),
        "sig_alg": obj.get("sig_alg"),
        "keyring": obj.get("keyring"),
        "params": obj.get("params"),
        "nonce": obj.get("nonce"),
    }

def admit_module(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "module": obj.get("module")}
