from __future__ import annotations
from typing import Any

def inspect_seed(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "target": obj.get("target"),
        "input_sha256": obj.get("input_sha256"),
        "size": obj.get("size"),
        "coverage_edges": obj.get("coverage_edges"),
        "format": obj.get("format"),
        "timeout_ms": obj.get("timeout_ms"),
        "nonce": obj.get("nonce"),
    }

def admit_seed(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "target": obj.get("target")}
