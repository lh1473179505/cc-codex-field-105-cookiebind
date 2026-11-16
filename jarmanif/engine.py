from __future__ import annotations
from typing import Any

def inspect_archive(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "main_class": obj.get("main_class"),
        "impl_title": obj.get("impl_title"),
        "sealing": obj.get("sealing"),
        "entries": obj.get("entries"),
        "svc_line": obj.get("svc_line"),
        "alg": obj.get("alg"),
        "nonce": obj.get("nonce"),
    }

def admit_archive(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "main_class": obj.get("main_class")}
