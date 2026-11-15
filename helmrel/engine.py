from __future__ import annotations
from typing import Any

def inspect_release(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "release": obj.get("release"),
        "chart": obj.get("chart"),
        "version": obj.get("version"),
        "ns": obj.get("ns"),
        "values_sha256": obj.get("values_sha256"),
        "kube": obj.get("kube"),
        "nonce": obj.get("nonce"),
    }

def admit_release(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "release": obj.get("release")}
