from __future__ import annotations
from typing import Any

def inspect_desc(desc: dict) -> dict:
    return {"kid": desc.get("kid"), "onion": desc.get("onion"), "client": desc.get("client"), "revision": desc.get("revision"), "nonce": desc.get("nonce")}

def admit_desc(desc: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "onion": desc.get("onion")}
