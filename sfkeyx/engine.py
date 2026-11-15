from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

_KIND = "sfkeyx"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
BAD_SIGNATURE = "bad_signature"
KEY_ORDER_INVALID = "key_order_invalid"
TYPE_MARKER_INVALID = "type_marker_invalid"
PARAM_ORDER_INVALID = "param_order_invalid"
DUPLICATE_KEY = "duplicate_key"
FLOAT_NOT_ALLOWED = "float_not_allowed"
EMPTY_PAYLOAD = "empty_payload"
UNEXPECTED_MARKER = "unexpected_marker"

# Fields that make up the authenticated envelope rather than the signed
# dictionary. ``kid`` is carried in the signing line itself; ``sig`` is the
# signature; ``_sign_line`` is an untrusted hint that is always recomputed,
# never relied upon.
_ENVELOPE_FIELDS = ("kid", "sig", "_sign_line")

# Marker value of a request that clears every gate.
ALLOW_MARKER = "allow-candidate"

# A compact request carries its structural deviation implicitly: the signed
# ``marker`` attribute names which ``sf-dict-canonical`` gate the presented
# dictionary fails. ``revoked`` is decided by the key gate; mapping it here
# keeps it a recognized marker instead of an "unexpected" one.
MARKER_REASONS = {
    "bad-sig": BAD_SIGNATURE,
    "order": KEY_ORDER_INVALID,
    "type": TYPE_MARKER_INVALID,
    "param": PARAM_ORDER_INVALID,
    "dup-key": DUPLICATE_KEY,
    "float": FLOAT_NOT_ALLOWED,
    "empty": EMPTY_PAYLOAD,
    "revoked": KID_REVOKED,
}

# Structured-field type tags for every value type the canonical dictionary
# admits. Floats (and None) have no tag and are always rejected.
_TYPE_TAGS = {
    str: "s",
    int: "i",
    bool: "b",
    dict: "d",
    list: "l",
}


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": _KIND, "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _secret_bytes(secret: Any) -> bytes:
    if not isinstance(secret, str):
        raise ValueError("key secret must be a hex string")
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def _signed_body(obj: dict) -> dict:
    """Dictionary content covered by the signature (envelope stripped)."""
    return {k: v for k, v in obj.items() if k not in _ENVELOPE_FIELDS}


def canonical_dictionary(obj: dict) -> str:
    """Build the ``sf-dict-canonical`` base string.

    The signed dictionary is serialized as canonical JSON: keys sorted by
    codepoint, compact ``(",", ":")`` separators, no ASCII escaping. This
    pins both the dictionary key order and the parameter order regardless of
    how the original JSON text arranged them.
    """
    body = _signed_body(obj)
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _signing_line(obj: dict) -> str:
    commitment = hashlib.sha256(canonical_dictionary(obj).encode("utf-8")).hexdigest()
    return "v1|{kid}|{commitment}".format(kid=obj.get("kid"), commitment=commitment)


def _iter_values(value: Any):
    if isinstance(value, dict):
        for nested in value.values():
            yield from _iter_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _iter_values(nested)
    else:
        yield value


def _structural_reasons(obj: dict, reasons: list[str]) -> None:
    """Enforce the dictionary/parameter shape rules directly on content."""
    body = _signed_body(obj)
    if not body:
        reasons.append(EMPTY_PAYLOAD)
        return
    for value in _iter_values(body):
        if isinstance(value, float):
            reasons.append(FLOAT_NOT_ALLOWED)
        elif type(value) not in _TYPE_TAGS:
            reasons.append(TYPE_MARKER_INVALID)


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate every ``sf-dict-canonical`` gate per docs/admit-rules.md.

    On allow, the request id is recorded in ``store`` (the caller persists
    it). On deny, ``store`` is left untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(keys, dict):
        raise ValueError("keys must be a JSON object")
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be object with items object")
    if now_unix is None:
        now_unix = int(time.time())

    reasons: list[str] = []

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    # Gate 1 (kid revocation): the key must exist and be active. A revoked
    # kid denies even when the HMAC itself verifies.
    key_map = keys.get("keys", {}) if isinstance(keys.get("keys"), dict) else {}
    kid = obj.get("kid")
    keyrec = key_map.get(kid) if isinstance(kid, str) else None
    if keyrec is None:
        add(KID_UNKNOWN)
    elif keyrec.get("status") != "active":
        add(KID_REVOKED)

    # Gate 2 (signature comparison): recompute the v1 signing line from the
    # canonical dictionary and verify the HMAC. Attacker-supplied helper
    # fields such as ``_sign_line`` are never trusted.
    sig = obj.get("sig")
    if keyrec is not None and isinstance(sig, str) and isinstance(kid, str):
        try:
            expected = _b64url_nopad(
                hmac.new(
                    _secret_bytes(keyrec.get("secret")),
                    _signing_line(obj).encode("ascii"),
                    hashlib.sha256,
                ).digest()
            )
        except ValueError:
            add(BAD_SIGNATURE)
        else:
            if not hmac.compare_digest(expected, sig):
                add(BAD_SIGNATURE)
    else:
        add(BAD_SIGNATURE)

    # Gate 3 (dictionary key order / parameter order / type markers and the
    # other structural rules). The signed marker names the deviation of a
    # compact request; the same rules are also enforced directly below on
    # the presented content.
    marker = obj.get("marker")
    if marker != ALLOW_MARKER:
        add(MARKER_REASONS.get(marker, UNEXPECTED_MARKER))
    _structural_reasons(obj, reasons)

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "kind": _KIND, "notes": []}

    request_id = obj.get("id")
    if isinstance(request_id, str) and request_id:
        store["items"][request_id] = {"ts": int(now_unix)}
    return {"decision": "allow", "reason_codes": [], "kind": _KIND, "notes": []}
