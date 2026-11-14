from __future__ import annotations
from typing import Any

def inspect_request(request: dict) -> dict:
    return {
        "method": request.get("method"),
        "authority": request.get("authority"),
        "path": request.get("path"),
        "kid": request.get("kid"),
        "covered": list(request.get("covered") or []),
        "nonce": request.get("nonce"),
    }

def admit_request(request: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "authority": request.get("authority"), "path": request.get("path")}
