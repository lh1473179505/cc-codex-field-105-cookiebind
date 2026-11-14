from __future__ import annotations
from typing import Any

def inspect_svid(svid: dict) -> dict:
    return {"kid": svid.get("kid"), "sub": svid.get("sub"), "aud": svid.get("aud"), "td": svid.get("td"), "nonce": svid.get("nonce")}

def admit_svid(svid: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    return {"decision": "deny", "reason_codes": ["not_implemented"], "sub": svid.get("sub")}
