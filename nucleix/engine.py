from __future__ import annotations
from typing import Any

def inspect_nuclei_template(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "template_id": obj.get("template_id"),
        "protocol": obj.get("protocol"),
        "matcher": obj.get("matcher"),
        "extractor": obj.get("extractor"),
        "request_headers": obj.get("request_headers"),
        "nonce": obj.get("nonce"),
    }

def admit_nuclei_template(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "template_id": obj.get("template_id")}
