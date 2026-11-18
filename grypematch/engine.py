from __future__ import annotations
from typing import Any

def inspect_grype_match(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "package_purl": obj.get("package_purl"),
        "cve": obj.get("cve"),
        "fix_state": obj.get("fix_state"),
        "severity": obj.get("severity"),
        "ignore": obj.get("ignore"),
        "nonce": obj.get("nonce"),
    }

def admit_grype_match(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "package_purl": obj.get("package_purl")}
