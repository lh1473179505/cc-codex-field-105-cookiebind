from __future__ import annotations
from typing import Any

def inspect_statement(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "product_purl": obj.get("product_purl"),
        "cve": obj.get("cve"),
        "status": obj.get("status"),
        "justification": obj.get("justification"),
        "action_statement": obj.get("action_statement"),
        "issued_at": obj.get("issued_at"),
        "nonce": obj.get("nonce"),
    }

def admit_statement(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "product_purl": obj.get("product_purl")}
