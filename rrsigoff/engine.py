from __future__ import annotations
from typing import Any

def inspect_answer(answer: dict) -> dict:
    return {
        "kid": answer.get("kid"),
        "signer": answer.get("signer"),
        "type_covered": answer.get("type_covered"),
        "names": sorted({rr.get("name") for rr in (answer.get("rrset") or [])}),
        "inception": answer.get("inception"),
        "expiration": answer.get("expiration"),
        "nonce": answer.get("nonce"),
    }

def admit_answer(answer: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "signer": answer.get("signer"), "type_covered": answer.get("type_covered")}
