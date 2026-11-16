from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_otp(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "public_id": obj.get("public_id"),
        "session": obj.get("session"),
        "use": obj.get("use"),
        "nonce": obj.get("nonce"),
    }

def admit_otp(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    public_id = obj.get("public_id")
    reason_codes: list[str] = []

    if not isinstance(public_id, str) or len(public_id) != policy.get("public_id_len"):
        reason_codes.append("public_id_len")

    id_entry = policy.get("ids", {}).get(public_id) if isinstance(public_id, str) else None
    if id_entry is None:
        reason_codes.append("unknown_public_id")

    session = obj.get("session")
    use = obj.get("use")
    if not isinstance(session, int) or isinstance(session, bool):
        reason_codes.append("invalid_session")
    elif id_entry is not None and session < id_entry["session_min"]:
        reason_codes.append("session_out_of_range")

    if not isinstance(use, int) or isinstance(use, bool):
        reason_codes.append("invalid_use")
    elif id_entry is not None and not (id_entry["use_min"] <= use <= id_entry["use_max"]):
        reason_codes.append("use_out_of_range")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if key_entry is None:
        reason_codes.append("unknown_key")
    elif key_entry.get("status") != "active":
        reason_codes.append("key_revoked")

    if key_entry is not None and not _signature_valid(obj, key_entry):
        reason_codes.append("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool) or not (
        now_unix - policy.get("max_age_seconds", 0) <= iat <= now_unix + policy.get("clock_skew_seconds", 0)
    ):
        reason_codes.append("time_window")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reason_codes.append("invalid_nonce")
    elif nonce in store.get("items", {}):
        reason_codes.append("nonce_replay")

    report = {
        "decision": "deny" if reason_codes else "allow",
        "reason_codes": reason_codes,
        "public_id": public_id,
    }
    if not reason_codes:
        store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return report


def _signature_valid(obj: dict, key_entry: dict) -> bool:
    sig = obj.get("sig")
    if not isinstance(sig, str):
        return False
    try:
        secret = bytes.fromhex(key_entry["secret"])
    except (KeyError, TypeError, ValueError):
        return False
    line = "v1|{}|{}|{}|{}|{}|{}".format(
        obj.get("kid"),
        obj.get("public_id"),
        obj.get("session"),
        obj.get("use"),
        obj.get("iat"),
        obj.get("nonce"),
    ).encode("utf-8")
    expected = base64.urlsafe_b64encode(
        hmac.new(secret, line, hashlib.sha256).digest()
    ).rstrip(b"=")
    return hmac.compare_digest(expected, sig.encode("utf-8"))
