from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_SIGNING_VERSION = "v1"
_SIGNING_FIELDS = (
    "kid",
    "bucket",
    "subject",
    "cost",
    "window",
    "burst",
    "iat",
    "nonce",
)
_TEXT_FIELDS = ("kid", "bucket", "subject", "window", "nonce", "sig")
_INT_FIELDS = ("cost", "burst", "iat")


def inspect_ticket(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "bucket": obj.get("bucket"),
        "subject": obj.get("subject"),
        "cost": obj.get("cost"),
        "window": obj.get("window"),
        "nonce": obj.get("nonce"),
    }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _signing_line(obj: dict) -> str:
    return _SIGNING_VERSION + "|" + "|".join(
        str(obj[field]) for field in _SIGNING_FIELDS
    )


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def admit_ticket(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    bucket_name = obj.get("bucket")
    report_bucket = bucket_name if isinstance(bucket_name, str) else ""
    reason_codes: list[str] = []

    shape_ok = all(
        isinstance(obj.get(field), str) for field in _TEXT_FIELDS
    ) and all(_is_int(obj.get(field)) for field in _INT_FIELDS)
    if not shape_ok:
        reason_codes.append("malformed_ticket")

    buckets = policy.get("buckets", {}) if isinstance(policy, dict) else {}
    bucket = (
        buckets.get(bucket_name)
        if shape_ok and isinstance(buckets, dict)
        else None
    )
    if not isinstance(bucket, dict):
        reason_codes.append("unknown_bucket")
        bucket = None

    if shape_ok:
        subject = obj["subject"]
        if bucket is not None:
            prefixes = bucket.get("subjects_prefix", [])
            if not any(
                isinstance(prefix, str) and subject.startswith(prefix)
                for prefix in prefixes
            ):
                reason_codes.append("subject_prefix_denied")

            if obj["window"] not in bucket.get("windows", []):
                reason_codes.append("window_denied")

            if obj["burst"] > bucket["burst_max"]:
                reason_codes.append("burst_exceeded")

            if obj["cost"] > bucket["cost_max"]:
                reason_codes.append("cost_exceeded")

        cost = obj["cost"]
        if cost < 0:
            reason_codes.append("negative_cost")
        elif cost == 0:
            reason_codes.append("cost_invalid")

        key_entry = (
            keys.get("keys", {}).get(obj["kid"])
            if isinstance(keys, dict)
            else None
        )
        if not isinstance(key_entry, dict):
            reason_codes.append("unknown_key")
        else:
            try:
                secret = bytes.fromhex(key_entry.get("secret", ""))
            except (TypeError, ValueError):
                secret = None
                reason_codes.append("bad_signature")
            if secret is not None:
                digest = hmac.new(
                    secret,
                    _signing_line(obj).encode("utf-8"),
                    hashlib.sha256,
                ).digest()
                if not hmac.compare_digest(_b64url_nopad(digest), obj["sig"]):
                    reason_codes.append("bad_signature")
            if key_entry.get("status") != "active":
                reason_codes.append("key_revoked")

        iat = obj["iat"]
        skew = policy.get("clock_skew_seconds", 0) if isinstance(policy, dict) else 0
        max_age = policy.get("max_age_seconds", 0) if isinstance(policy, dict) else 0
        if iat - now_unix > skew:
            reason_codes.append("iat_skew")
        if now_unix - iat > max_age:
            reason_codes.append("ticket_expired")

        items = store.get("items", {}) if isinstance(store, dict) else {}
        if obj["nonce"] in items:
            reason_codes.append("nonce_replayed")

    if reason_codes:
        return {
            "decision": "deny",
            "reason_codes": reason_codes,
            "bucket": report_bucket,
        }

    store.setdefault("items", {})[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "bucket": report_bucket}
