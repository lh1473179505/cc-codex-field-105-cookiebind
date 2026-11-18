from __future__ import annotations
from typing import Any

def inspect_event(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "pid": obj.get("pid"),
        "cpu": obj.get("cpu"),
        "event_type": obj.get("event_type"),
        "sample_freq": obj.get("sample_freq"),
        "privileged": obj.get("privileged"),
        "paranoid": obj.get("paranoid"),
        "nonce": obj.get("nonce"),
    }

def admit_event(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "profile": obj.get("profile")}
