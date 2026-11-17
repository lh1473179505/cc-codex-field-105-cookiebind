from __future__ import annotations
from typing import Any

def inspect_export(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "export_path": obj.get("export_path"),
        "root_squash": obj.get("root_squash"),
        "client_cidr": obj.get("client_cidr"),
        "permissions": obj.get("permissions"),
        "anon_uid": obj.get("anon_uid"),
        "anon_gid": obj.get("anon_gid"),
        "nonce": obj.get("nonce"),
    }

def admit_export(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "export_path": obj.get("export_path")}
