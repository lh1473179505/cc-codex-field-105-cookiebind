from __future__ import annotations
from typing import Any

def inspect_provenance(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "builder": obj.get("builder"),
        "repo_ref": obj.get("repo_ref"),
        "source_digest": obj.get("source_digest"),
        "subject": obj.get("subject"),
        "subject_digest": obj.get("subject_digest"),
        "build_level": obj.get("build_level"),
        "nonce": obj.get("nonce"),
    }

def admit_provenance(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "subject": obj.get("subject")}
