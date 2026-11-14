from __future__ import annotations
from typing import Any

def inspect_bundle(bundle: dict) -> dict:
    root = bundle.get("root") or {}
    dis = bundle.get("discharge") or {}
    req = bundle.get("request") or {}
    return {
        "root_kid": root.get("kid"),
        "root_identifier": root.get("identifier"),
        "caveat_types": [c.get("type") for c in (root.get("caveats") or [])],
        "has_discharge": bundle.get("discharge") is not None,
        "discharge_kid": dis.get("kid") if bundle.get("discharge") else None,
        "request_path": req.get("path"),
        "request_method": req.get("method"),
        "nonce": bundle.get("nonce"),
    }

def admit_bundle(bundle: dict, keys: dict, policy: dict, nonce_store: dict, now_unix: int) -> dict:
    root = bundle.get("root") or {}
    dis = bundle.get("discharge")
    req = bundle.get("request") or {}
    return {
        "decision": "deny",
        "reason_codes": ["not_implemented"],
        "root_identifier": root.get("identifier"),
        "discharge_identifier": (dis or {}).get("identifier") if dis else None,
        "path": req.get("path"),
    }
