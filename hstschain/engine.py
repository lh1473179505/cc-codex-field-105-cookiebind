from __future__ import annotations
from typing import Any

def inspect_chain(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "host": obj.get("host"),
        "max_age": obj.get("max_age"),
        "include_sub": obj.get("include_sub"),
        "preload": obj.get("preload"),
        "report_uri": obj.get("report_uri"),
        "ct_log": obj.get("ct_log"),
        "nonce": obj.get("nonce"),
    }

def admit_chain(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "host": obj.get("host")}
