from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_idtoken(tok: dict) -> dict:
    return {"kid": tok.get("kid"), "iss": tok.get("iss"), "aud": tok.get("aud"), "azp": tok.get("azp"), "nonce": tok.get("nonce"), "acr": tok.get("acr")}


_STRING_FIELDS = ("kid", "iss", "azp", "sub", "acr", "nonce", "sig")
_INT_FIELDS = ("auth_time", "exp")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _normalized_aud(tok: dict) -> list[str] | None:
    aud = tok.get("aud")
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list) and aud and all(isinstance(item, str) for item in aud):
        return list(aud)
    return None


def _well_formed(tok: Any) -> bool:
    if not isinstance(tok, dict):
        return False
    if _normalized_aud(tok) is None:
        return False
    for field in _STRING_FIELDS:
        if not isinstance(tok.get(field), str) or not tok[field]:
            return False
    for field in _INT_FIELDS:
        value = tok.get(field)
        if not isinstance(value, int) or isinstance(value, bool):
            return False
    return True


def _signing_input(tok: dict, aud: list[str]) -> str:
    return "|".join((
        "v1",
        str(tok["kid"]),
        str(tok["iss"]),
        ",".join(aud),
        str(tok["azp"]),
        str(tok["sub"]),
        str(tok["acr"]),
        str(tok["auth_time"]),
        str(tok["exp"]),
        str(tok["nonce"]),
    ))


def admit_idtoken(tok: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reason_codes: list[str] = []
    sub = tok.get("sub") if isinstance(tok, dict) else None

    if not _well_formed(tok):
        return {"decision": "deny", "reason_codes": ["malformed_token"], "sub": sub}

    aud = _normalized_aud(tok)

    key_entry = keys.get("keys", {}).get(tok["kid"])
    if not isinstance(key_entry, dict) or not isinstance(key_entry.get("secret"), str):
        reason_codes.append("unknown_kid")
    else:
        try:
            secret = bytes.fromhex(key_entry["secret"])
        except ValueError:
            secret = b""
            reason_codes.append("malformed_key")
        if secret:
            digest = hmac.new(secret, _signing_input(tok, aud).encode("utf-8"), hashlib.sha256).digest()
            if not hmac.compare_digest(_b64url(digest), tok["sig"]):
                reason_codes.append("bad_signature")
        if key_entry.get("status") != "active":
            reason_codes.append("kid_revoked")

    if tok["iss"] not in policy.get("allowed_issuers", []):
        reason_codes.append("iss_not_allowed")

    allowed_audiences = policy.get("allowed_audiences", [])
    allowed_azp = policy.get("allowed_azp", [])
    if any(item not in allowed_audiences for item in aud):
        reason_codes.append("aud_not_allowed")
    if tok["azp"] not in allowed_azp:
        reason_codes.append("azp_not_allowed")
    if tok["azp"] not in aud:
        reason_codes.append("azp_not_in_aud")

    if tok["acr"] not in policy.get("required_acr", []):
        reason_codes.append("acr_not_satisfied")

    skew = int(policy.get("clock_skew_seconds", 0))
    if tok["auth_time"] > now_unix + skew:
        reason_codes.append("auth_time_in_future")
    if tok["exp"] < now_unix - skew:
        reason_codes.append("token_expired")

    items = store.setdefault("items", {})
    if tok["nonce"] in items:
        reason_codes.append("nonce_replayed")

    if reason_codes:
        return {"decision": "deny", "reason_codes": reason_codes, "sub": sub}

    items[tok["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "sub": sub}
