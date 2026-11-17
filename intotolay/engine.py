from __future__ import annotations
from typing import Any

def inspect_layout(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "supply_chain": obj.get("supply_chain"),
        "step_name": obj.get("step_name"),
        "pubkey_ids": obj.get("pubkey_ids"),
        "threshold": obj.get("threshold"),
        "artifact_rules": obj.get("artifact_rules"),
        "layout_sha256": obj.get("layout_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_layout(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "step_name": obj.get("step_name")}
