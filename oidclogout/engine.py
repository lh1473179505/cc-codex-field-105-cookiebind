from __future__ import annotations
from typing import Any

def inspect_logout(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "client_id": obj.get("client_id"),
        "issuer": obj.get("issuer"),
        "sid": obj.get("sid"),
        "post_logout_uri": obj.get("post_logout_uri"),
        "state": obj.get("state"),
        "ui_locales": obj.get("ui_locales"),
        "nonce": obj.get("nonce"),
    }

def admit_logout(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "client_id": obj.get("client_id")}
