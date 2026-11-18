from __future__ import annotations
from typing import Any

def inspect_cvss_vector(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "version": obj.get("version"),
        "vector": obj.get("vector"),
        "metrics": obj.get("metrics"),
        "score": obj.get("score"),
        "severity": obj.get("severity"),
        "environmental": obj.get("environmental"),
        "nonce": obj.get("nonce"),
    }

def admit_cvss_vector(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "vector": obj.get("vector")}
