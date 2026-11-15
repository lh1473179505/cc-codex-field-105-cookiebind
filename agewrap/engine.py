from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

VERSION = "v1"

_STRING_FIELDS = ("kid", "recipient", "alg", "aad", "ct_hash", "nonce", "sig")


def _signing_input(box: dict) -> str:
    return "|".join((
        VERSION,
        box["kid"],
        box["recipient"],
        box["alg"],
        box["aad"],
        box["ct_hash"],
        str(box["iat"]),
        box["nonce"],
    ))


def _expected_sig(secret_hex: str, message: str) -> str | None:
    try:
        secret = bytes.fromhex(secret_hex)
    except (TypeError, ValueError):
        return None
    digest = hmac.new(secret, message.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _is_well_formed(box: Any) -> bool:
    if not isinstance(box, dict):
        return False
    if any(not isinstance(box.get(field), str) or not box[field] for field in _STRING_FIELDS):
        return False
    iat = box.get("iat")
    return isinstance(iat, int) and not isinstance(iat, bool)


def inspect_box(box: dict) -> dict:
    return {"kid": box.get("kid"), "recipient": box.get("recipient"), "aad": box.get("aad"), "alg": box.get("alg"), "nonce": box.get("nonce")}

def admit_box(box: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    recipient = box.get("recipient") if isinstance(box, dict) else None

    if not _is_well_formed(box):
        return {"decision": "deny", "reason_codes": ["malformed_box"], "recipient": recipient}

    reason_codes: list[str] = []

    # Gate 1: HMAC verification and kid revocation.
    entry = keys.get("keys", {}).get(box["kid"])
    if entry is None:
        reason_codes.append("unknown_kid")
    else:
        if entry.get("status") != "active":
            reason_codes.append("kid_revoked")
        expected = _expected_sig(entry.get("secret", ""), _signing_input(box))
        if expected is None:
            reason_codes.append("malformed_key")
        elif not hmac.compare_digest(expected, box["sig"]):
            reason_codes.append("bad_hmac")

    # Gate 2: recipient/alg allowlists and downgrade ban.
    if box["recipient"] not in policy.get("allowed_recipients", ()):
        reason_codes.append("recipient_not_allowed")
    if box["alg"] not in policy.get("allowed_algs", ()):
        reason_codes.append("alg_not_allowed")
    if box["alg"] in policy.get("deny_alg_downgrade", ()):
        reason_codes.append("alg_downgrade_denied")

    # Gate 3: AAD prefix.
    prefixes = policy.get("required_aad_prefixes", ())
    if not any(box["aad"].startswith(prefix) for prefix in prefixes):
        reason_codes.append("aad_prefix_mismatch")

    # Gate 4: iat time window and nonce replay store.
    age = now_unix - box["iat"]
    if age > policy.get("max_age_seconds", 0) or -age > policy.get("clock_skew_seconds", 0):
        reason_codes.append("iat_out_of_window")
    if box["nonce"] in store.get("items", {}):
        reason_codes.append("nonce_replayed")

    if reason_codes:
        return {"decision": "deny", "reason_codes": reason_codes, "recipient": box["recipient"]}

    store.setdefault("items", {})[box["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "recipient": box["recipient"]}
