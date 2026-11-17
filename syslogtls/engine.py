from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_SIGNING_FIELDS = (
    "kid",
    "receiver",
    "peer_cn",
    "peer_spiffe",
    "facility",
    "severity",
    "app",
    "message_length",
    "iat",
    "nonce",
)


def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{receiver}|{peer_cn}|{peer_spiffe}|{facility}|{severity}|{app}|{message_length}|{iat}|{nonce}".format(
        **{name: obj.get(name) for name in _SIGNING_FIELDS}
    )


def _is_json_integer(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def inspect_event(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "receiver": obj.get("receiver"),
        "peer_cn": obj.get("peer_cn"),
        "peer_spiffe": obj.get("peer_spiffe"),
        "facility": obj.get("facility"),
        "severity": obj.get("severity"),
        "app": obj.get("app"),
        "message_length": obj.get("message_length"),
        "nonce": obj.get("nonce"),
    }

def admit_event(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    app = obj.get("app")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if not isinstance(key_entry, dict):
        reasons.append("unknown_kid")
    else:
        if key_entry.get("status") != "active":
            reasons.append("key_revoked")
        try:
            secret = bytes.fromhex(key_entry.get("secret", ""))
        except (TypeError, ValueError):
            secret = b""
        digest = hmac.new(
            secret,
            _signing_line(obj).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        expected_sig = (
            base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        )
        given_sig = obj.get("sig")
        if not isinstance(given_sig, str) or not hmac.compare_digest(
            expected_sig, given_sig
        ):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    if not _is_json_integer(iat):
        reasons.append("iat_invalid")
    else:
        clock_skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat - now_unix > clock_skew:
            reasons.append("iat_in_future")
        elif now_unix - iat > max_age:
            reasons.append("iat_too_old")

    receiver_name = obj.get("receiver")
    receiver = policy.get("receivers", {}).get(receiver_name)
    if not isinstance(receiver, dict):
        reasons.append("receiver_not_allowed")
        receiver = None

    if receiver is not None:
        identities = receiver.get("identities", {})
        peer_cn = obj.get("peer_cn")
        peer_spiffe = obj.get("peer_spiffe")
        if not isinstance(peer_cn, str) or peer_cn not in identities:
            reasons.append("peer_cn_not_allowed")
            allowed_spiffes = []
        else:
            allowed_spiffes = identities.get(peer_cn, [])
        if not isinstance(peer_spiffe, str) or peer_spiffe not in allowed_spiffes:
            reasons.append("peer_spiffe_not_allowed")

        facility = obj.get("facility")
        if not _is_json_integer(facility) or facility not in receiver.get(
            "facilities", []
        ):
            reasons.append("facility_not_allowed")

        severity = obj.get("severity")
        if not _is_json_integer(severity) or severity not in receiver.get(
            "severities", []
        ):
            reasons.append("severity_not_allowed")

        if not isinstance(app, str) or app not in receiver.get("apps", []):
            reasons.append("app_not_allowed")

        message_length = obj.get("message_length")
        length_min = receiver.get("message_length_min")
        length_max = receiver.get("message_length_max")
        if (
            not _is_json_integer(message_length)
            or not _is_json_integer(length_min)
            or not _is_json_integer(length_max)
            or not (length_min <= message_length <= length_max)
        ):
            reasons.append("message_length_out_of_range")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in store.setdefault("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "app": app}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "app": app}
