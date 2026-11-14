from __future__ import annotations
from typing import Any

def inspect_mail(mail: dict) -> dict:
    return {"kid": mail.get("kid"), "d": mail.get("d"), "s": mail.get("s"), "from_domain": mail.get("from_domain"), "arc_cv": mail.get("arc_cv"), "nonce": mail.get("nonce")}

def admit_mail(mail: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "d": mail.get("d")}
