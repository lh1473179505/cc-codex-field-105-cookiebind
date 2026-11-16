from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_CRED_FIELDS = ("kid", "rp_id", "user_id", "aaguid", "uv", "nonce", "iat", "sig")


def inspect_cred(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "rp_id": obj.get("rp_id"),
        "user_id": obj.get("user_id"),
        "aaguid": obj.get("aaguid"),
        "uv": obj.get("uv"),
        "nonce": obj.get("nonce"),
    }


def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{rp_id}|{user_id}|{aaguid}|{uv}|{iat}|{nonce}".format(**obj)


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def admit_cred(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    rp_id = obj.get("rp_id")
    report: dict[str, Any] = {"decision": "deny", "reason_codes": [], "rp_id": rp_id}
    reason_codes: list[str] = report["reason_codes"]

    if not all(field in obj for field in _CRED_FIELDS):
        reason_codes.append("malformed_cred")
        return report

    iat = obj["iat"]
    if not isinstance(iat, int) or isinstance(iat, bool):
        reason_codes.append("malformed_cred")
        return report

    key_entries = keys.get("keys", {})
    key = key_entries.get(obj["kid"])
    if not isinstance(key, dict) or "secret" not in key:
        reason_codes.append("unknown_kid")
        return report

    if key.get("status") != "active":
        reason_codes.append("key_revoked")

    try:
        secret = bytes.fromhex(key["secret"])
        provided_sig = _b64url_decode(str(obj["sig"]))
        expected_sig = hmac.new(
            secret, _signing_line(obj).encode("utf-8"), hashlib.sha256
        ).digest()
        sig_ok = hmac.compare_digest(provided_sig, expected_sig)
    except (ValueError, TypeError):
        sig_ok = False
    if not sig_ok:
        reason_codes.append("bad_signature")

    rps = policy.get("rps", {})
    rp = rps.get(rp_id)
    if not isinstance(rp, dict):
        reason_codes.append("rp_not_allowed")
        return report

    if obj["aaguid"] not in rp.get("aaguids", []):
        reason_codes.append("aaguid_not_allowed")

    user_id = obj["user_id"]
    prefixes = rp.get("user_prefix", [])
    if not isinstance(user_id, str) or not any(
        user_id.startswith(prefix) for prefix in prefixes
    ):
        reason_codes.append("user_prefix_denied")

    if rp.get("require_uv") and obj["uv"] != 1:
        reason_codes.append("uv_required")

    skew = policy.get("clock_skew_seconds", 60)
    max_age = policy.get("max_age_seconds", 300)
    if iat > now_unix + skew:
        reason_codes.append("iat_in_future")
    elif iat < now_unix - max_age:
        reason_codes.append("iat_expired")

    items = store.setdefault("items", {})
    if obj["nonce"] in items:
        reason_codes.append("nonce_replayed")

    if reason_codes:
        return report

    items[obj["nonce"]] = {"ts": now_unix}
    report["decision"] = "allow"
    return report
