from __future__ import annotations
from typing import Any

def inspect_report(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "org": obj.get("org"),
        "domain": obj.get("domain"),
        "report_id": obj.get("report_id"),
        "begin": obj.get("begin"),
        "end": obj.get("end"),
        "records": obj.get("records"),
        "total_count": obj.get("total_count"),
        "report_sha256": obj.get("report_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_report(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "report_id": obj.get("report_id")}
