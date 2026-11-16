from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_desc(desc: dict) -> dict:
    return {"kid": desc.get("kid"), "onion": desc.get("onion"), "client": desc.get("client"), "revision": desc.get("revision"), "nonce": desc.get("nonce")}

_REQUIRED = ("kid", "onion", "client", "revision", "iat", "nonce", "sig")

def _signing_input(desc: dict) -> bytes:
    return "v1|{kid}|{onion}|{client}|{revision}|{iat}|{nonce}".format(**desc).encode("utf-8")

def _expected_sig(secret_hex: str, desc: dict) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), _signing_input(desc), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_desc(desc: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    missing = [k for k in _REQUIRED if k not in desc]
    if missing:
        raise ValueError("desc missing fields: " + ",".join(missing))
    if not isinstance(desc["revision"], int) or not isinstance(desc["iat"], int):
        raise ValueError("revision and iat must be integers")

    reasons: list[str] = []

    key_entry = (keys.get("keys") or {}).get(desc["kid"])
    if key_entry is None:
        reasons.append("kid_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("kid_revoked")
    elif not hmac.compare_digest(_expected_sig(key_entry["secret"], desc), str(desc["sig"])):
        reasons.append("bad_sig")

    if desc["onion"] not in (policy.get("allowed_onions") or []):
        reasons.append("onion_not_allowed")
    if desc["client"] not in (policy.get("allowed_clients") or []):
        reasons.append("client_not_allowed")

    if desc["revision"] < int(policy.get("min_revision", 0)):
        reasons.append("revision_too_low")

    max_age = int(policy.get("max_age_seconds", 0))
    skew = int(policy.get("clock_skew_seconds", 0))
    if desc["iat"] < now_unix - max_age:
        reasons.append("stale")
    elif desc["iat"] > now_unix + skew:
        reasons.append("future_iat")

    items = store.setdefault("items", {})
    if desc["nonce"] in items:
        reasons.append("replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "onion": desc.get("onion")}

    items[desc["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "onion": desc.get("onion")}
