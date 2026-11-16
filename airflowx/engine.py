from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_SIGNING_VERSION = "v1"
_REQUIRED_FIELDS = ("kid", "dag_id", "owner", "pool", "queue", "iat", "nonce", "sig")
_STRING_FIELDS = ("kid", "dag_id", "owner", "pool", "queue", "nonce", "sig")

def inspect_run(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "dag_id": obj.get("dag_id"),
        "owner": obj.get("owner"),
        "pool": obj.get("pool"),
        "queue": obj.get("queue"),
        "nonce": obj.get("nonce"),
    }


def _signing_line(obj: dict) -> str:
    return "|".join((
        _SIGNING_VERSION,
        str(obj["kid"]),
        str(obj["dag_id"]),
        str(obj["owner"]),
        str(obj["pool"]),
        str(obj["queue"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ))


def _deny(dag_id: Any, reason_codes: list[str]) -> dict:
    return {"decision": "deny", "reason_codes": reason_codes, "dag_id": dag_id}


def admit_run(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    dag_id = obj.get("dag_id")

    malformed = (
        not isinstance(obj.get("iat"), int)
        or isinstance(obj.get("iat"), bool)
        or any(not isinstance(obj.get(field), str) for field in _STRING_FIELDS)
    )
    if malformed:
        return _deny(dag_id, ["malformed_run"])

    reason_codes: list[str] = []

    if any(
        substring in dag_id
        for substring in policy.get("dag_deny_substrings", [])
    ):
        reason_codes.append("dag_id_denied_substring")

    dag_entry = policy.get("dags", {}).get(dag_id)
    if dag_entry is None:
        reason_codes.append("dag_not_allowed")
    else:
        if obj["owner"] not in dag_entry.get("owners", []):
            reason_codes.append("owner_not_allowed")
        if obj["pool"] not in dag_entry.get("pools", []):
            reason_codes.append("pool_not_allowed")
        if obj["queue"] not in dag_entry.get("queues", []):
            reason_codes.append("queue_not_allowed")

    key_entry = keys.get("keys", {}).get(obj["kid"])
    if key_entry is None:
        reason_codes.append("unknown_kid")
    else:
        if key_entry.get("status") != "active":
            reason_codes.append("key_revoked")
        expected_sig = None
        try:
            secret = bytes.fromhex(key_entry["secret"])
            digest = hmac.new(
                secret,
                _signing_line(obj).encode("utf-8"),
                hashlib.sha256,
            ).digest()
            expected_sig = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        except (KeyError, TypeError, ValueError):
            expected_sig = None
        if expected_sig is None or not hmac.compare_digest(expected_sig, obj["sig"]):
            reason_codes.append("bad_signature")

    age = now_unix - obj["iat"]
    if age > policy.get("max_age_seconds", 0):
        reason_codes.append("iat_expired")
    if -age > policy.get("clock_skew_seconds", 0):
        reason_codes.append("iat_future")

    if obj["nonce"] in store.get("items", {}):
        reason_codes.append("nonce_replay")

    if reason_codes:
        return _deny(dag_id, reason_codes)

    store.setdefault("items", {})[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "dag_id": dag_id}
