from __future__ import annotations
from typing import Any

def inspect_msg(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "from_addr": obj.get("from_addr"),
        "return_path": obj.get("return_path"),
        "dkim_d": obj.get("dkim_d"),
        "arc_i": obj.get("arc_i"),
        "cv": obj.get("cv"),
        "body_sha256": obj.get("body_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_msg(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "from_addr": obj.get("from_addr")}
