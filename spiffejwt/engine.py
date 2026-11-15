from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any

SCHEME = "v1"

_REQUIRED_FIELDS = ("kid", "td", "sub", "aud", "iat", "exp", "nonce", "sig")

def inspect_svid(svid: dict) -> dict:
    return {"kid": svid.get("kid"), "sub": svid.get("sub"), "aud": svid.get("aud"), "td": svid.get("td"), "nonce": svid.get("nonce")}


def _signing_input(svid: dict) -> str:
    aud_csv = ",".join(svid["aud"])
    return "|".join((
        SCHEME,
        str(svid["kid"]),
        str(svid["td"]),
        str(svid["sub"]),
        aud_csv,
        str(svid["iat"]),
        str(svid["exp"]),
        str(svid["nonce"]),
    ))


def _well_formed(svid: Any) -> bool:
    if not isinstance(svid, dict):
        return False
    for field in _REQUIRED_FIELDS:
        if field not in svid:
            return False
    if not isinstance(svid["aud"], list) or not svid["aud"]:
        return False
    if not all(isinstance(item, str) and item for item in svid["aud"]):
        return False
    for field in ("kid", "td", "sub", "nonce", "sig"):
        if not isinstance(svid[field], str) or not svid[field]:
            return False
    for field in ("iat", "exp"):
        if not isinstance(svid[field], int) or isinstance(svid[field], bool):
            return False
    return True


def _signature_matches(svid: dict, secret_hex: str) -> bool:
    try:
        key_bytes = bytes.fromhex(secret_hex)
    except (TypeError, ValueError):
        return False
    digest = hmac.new(key_bytes, _signing_input(svid).encode("utf-8"), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return hmac.compare_digest(expected, svid["sig"])


def admit_svid(svid: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reason_codes: list[str] = []
    sub = svid.get("sub") if isinstance(svid, dict) else None

    if not _well_formed(svid):
        return {"decision": "deny", "reason_codes": ["malformed_svid"], "sub": sub}

    # Gate 1: key status and HMAC signature.
    key_bundle = (keys.get("keys") or {}).get(svid["kid"])
    if not isinstance(key_bundle, dict) or "secret" not in key_bundle:
        reason_codes.append("kid_unknown")
    else:
        if key_bundle.get("status") != "active":
            reason_codes.append("kid_revoked" if key_bundle.get("status") == "revoked" else "kid_inactive")
        if not _signature_matches(svid, key_bundle["secret"]):
            reason_codes.append("bad_signature")

    # Gate 2: trust domain and audience allowlists.
    allowed_td = policy.get("allowed_td", [])
    if svid["td"] not in allowed_td:
        reason_codes.append("td_not_allowed")
    allowed_aud = policy.get("allowed_aud", [])
    if any(item not in allowed_aud for item in svid["aud"]):
        reason_codes.append("aud_not_allowed")

    # Gate 3: subject must stay inside its claimed trust domain.
    if policy.get("sub_must_match_td", False):
        expected_prefix = "spiffe://" + svid["td"] + "/"
        if not svid["sub"].startswith(expected_prefix):
            reason_codes.append("sub_td_mismatch")

    # Gate 4: validity window and one-time nonce.
    skew = int(policy.get("clock_skew_seconds", 0))
    if now_unix < svid["iat"] - skew:
        reason_codes.append("not_valid_yet")
    if now_unix >= svid["exp"]:
        reason_codes.append("token_expired")

    items = store.setdefault("items", {})
    if svid["nonce"] in items:
        reason_codes.append("nonce_replayed")

    if reason_codes:
        return {"decision": "deny", "reason_codes": reason_codes, "sub": svid["sub"]}

    items[svid["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "sub": svid["sub"]}
