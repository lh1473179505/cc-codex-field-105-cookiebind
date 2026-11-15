from __future__ import annotations
from typing import Any

def inspect_challenge(ch: dict) -> dict:
    return {
        "kid": ch.get("kid"),
        "method": ch.get("method"),
        "host": ch.get("host"),
        "raw_path": ch.get("raw_path"),
        "query": ch.get("query"),
        "nonce": ch.get("nonce"),
    }

def admit_challenge(ch: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "path": ch.get("raw_path")}
