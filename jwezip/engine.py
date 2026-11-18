from __future__ import annotations
from typing import Any

def inspect_jwe(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "alg": obj.get("alg"),
        "enc": obj.get("enc"),
        "zip": obj.get("zip"),
        "jwe_kid": obj.get("jwe_kid"),
        "crit": obj.get("crit"),
        "nonce": obj.get("nonce"),
    }

def admit_jwe(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "jwe_kid": obj.get("jwe_kid")}
