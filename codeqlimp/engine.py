from __future__ import annotations
from typing import Any

def inspect_codeql_import(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "pack": obj.get("pack"),
        "query_id": obj.get("query_id"),
        "language": obj.get("language"),
        "severity": obj.get("severity"),
        "precision": obj.get("precision"),
        "metadata": obj.get("metadata"),
        "nonce": obj.get("nonce"),
    }

def admit_codeql_import(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "query_id": obj.get("query_id")}
