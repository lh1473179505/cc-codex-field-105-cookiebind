from __future__ import annotations
from typing import Any
from urllib.parse import urlparse

def inspect_plan(plan: dict) -> dict:
    u = urlparse(plan.get("url") or "")
    return {
        "method": plan.get("method"),
        "scheme": u.scheme,
        "host": u.hostname,
        "path": u.path,
        "kid": plan.get("kid"),
        "pin_ips": list(plan.get("pin_ips") or []),
        "redirects": list(plan.get("redirects") or []),
    }

def admit_plan(plan: dict, keys: dict, policy: dict, now_unix: int | None = None) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "host": None, "ips": []}
