from __future__ import annotations
from typing import Any

def inspect_program(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "prog_type": obj.get("prog_type"),
        "attach_type": obj.get("attach_type"),
        "license": obj.get("license"),
        "insn_count": obj.get("insn_count"),
        "map_refs": obj.get("map_refs"),
        "privileged": obj.get("privileged"),
        "nonce": obj.get("nonce"),
    }

def admit_program(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "prog_type": obj.get("prog_type")}
