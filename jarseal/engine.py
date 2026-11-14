from __future__ import annotations
from typing import Any

def inspect_archive(archive: dict) -> dict:
    return {
        "kid": archive.get("kid"),
        "main_class": archive.get("main_class"),
        "paths": [e.get("path") for e in (archive.get("entries") or [])],
        "nonce": archive.get("nonce"),
        "created": archive.get("created"),
    }

def admit_archive(archive: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "main_class": archive.get("main_class"), "paths": []}
