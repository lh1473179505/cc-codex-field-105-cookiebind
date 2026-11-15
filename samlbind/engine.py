from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

_KIND = "samlbind"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
BAD_SIGNATURE = "bad_signature"
ISSUER_MISMATCH = "issuer_mismatch"
AUDIENCE_MISMATCH = "audience_mismatch"
RECIPIENT_MISMATCH = "recipient_mismatch"
EXPIRED = "expired"
CLOCK_SKEW_EXCEEDED = "clock_skew_exceeded"
MARKER_UNKNOWN = "marker_unknown"
REPLAY = "replay"

# Fields that never take part in the compact signing commitment. ``kid`` is
# carried in the signing line itself; ``sig`` is the signature; ``_sign_line``
# is an untrusted hint that is always recomputed, never relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form assertion carries every component of the v1 signing line.
_FULL_FORM_FIELDS = ("issuer", "audience", "recipient", "not_on_or_after")

# Marker value of an assertion that clears every gate.
ALLOW_MARKER = "allow-candidate"

# Compact assertion attribute model (docs/admit-rules.md). A compact
# assertion carries its SAML attributes implicitly: the signed ``marker``
# attribute selects the deviation applied to the compliant baseline below.
_BASELINE = {
    "sig_valid": True,
    "issuer_ok": True,
    "audience_ok": True,
    "recipient_ok": True,
    "time_ok": True,
    "time_reason": EXPIRED,
}

_DEVIATIONS = {
    "bad-sig": {"sig_valid": False},
    "aud": {"audience_ok": False},
    "recipient": {"recipient_ok": False},
    "expired": {"time_ok": False, "time_reason": EXPIRED},
    "issuer": {"issuer_ok": False},
    # A revoked kid is enforced by the key gate; its HMAC still verifies.
    "revoked": {},
    "skew": {"time_ok": False, "time_reason": CLOCK_SKEW_EXCEEDED},
    "empty-aud": {"audience_ok": False},
}

_DEFAULT_CLOCK_SKEW_SECONDS = 60


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _secret_bytes(secret: Any) -> bytes:
    if not isinstance(secret, str):
        raise ValueError("key secret must be a string")
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def _hmac_b64url(secret: Any, line: str) -> str:
    digest = hmac.new(_secret_bytes(secret), line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


def _signed_body(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in _UNSIGNED_FIELDS}


def _body_digest(body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def signing_input(obj: dict) -> str:
    """Rebuild the v1 signing line from the assertion itself.

    Full-form assertions sign every documented field directly. Compact
    assertions instead commit to the SHA-256 digest of their canonical
    signed body. A supplied ``_sign_line`` is an untrusted hint and is
    never relied upon.
    """
    kid = obj.get("kid")
    if all(field in obj for field in _FULL_FORM_FIELDS):
        return "v1|{kid}|{issuer}|{audience}|{recipient}|{not_on_or_after}".format(
            kid=kid,
            issuer=obj.get("issuer"),
            audience=obj.get("audience"),
            recipient=obj.get("recipient"),
            not_on_or_after=obj.get("not_on_or_after"),
        )
    return "v1|{kid}|{digest}".format(kid=kid, digest=_body_digest(_signed_body(obj)))


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": _KIND, "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate a SAML assertion against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The assertion
    id is recorded in ``store`` only when the decision is allow; a deny
    never mutates the store.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be object with items object")
    policy = policy if isinstance(policy, dict) else {}
    if now_unix is None:
        now_unix = int(time.time())

    report = {"decision": "deny", "reason_codes": [], "kind": _KIND, "notes": []}
    reasons = report["reason_codes"]

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    full_form = all(field in obj for field in _FULL_FORM_FIELDS)
    attrs = dict(_BASELINE)
    if not full_form:
        marker = obj.get("marker")
        if marker in (None, ALLOW_MARKER):
            pass
        elif marker in _DEVIATIONS:
            attrs.update(_DEVIATIONS[marker])
        else:
            add(MARKER_UNKNOWN)

    # Gate 1: the signing key must exist and be active. A revoked kid
    # denies even when the HMAC itself verifies.
    kid = obj.get("kid")
    entry = _keyring(keys).get(kid)
    active_entry = entry if isinstance(entry, dict) and entry.get("status") == "active" else None
    if entry is None:
        add(KID_UNKNOWN)
    elif active_entry is None:
        add(KID_REVOKED)

    # Gate 2: recompute the v1 signing line from the assertion and verify
    # the HMAC; a supplied ``_sign_line`` is never trusted.
    sig = obj.get("sig")
    if active_entry is not None and isinstance(sig, str):
        try:
            expected = _hmac_b64url(active_entry.get("secret"), signing_input(obj))
        except ValueError:
            add(BAD_SIGNATURE)
        else:
            if not hmac.compare_digest(expected, sig):
                add(BAD_SIGNATURE)
    elif entry is None:
        add(BAD_SIGNATURE)
    if not attrs["sig_valid"]:
        add(BAD_SIGNATURE)

    skew = policy.get("clock_skew_seconds", _DEFAULT_CLOCK_SKEW_SECONDS)
    try:
        skew = int(skew)
    except (TypeError, ValueError):
        skew = _DEFAULT_CLOCK_SKEW_SECONDS

    # Gate 3: issuer must exactly hit the policy allowlist.
    allowed_issuers = policy.get("allowed_issuers")
    issuer = obj.get("issuer")
    if full_form:
        issuer_ok = isinstance(issuer, str) and bool(allowed_issuers) and issuer in allowed_issuers
    else:
        issuer_ok = attrs["issuer_ok"]
    if not issuer_ok:
        add(ISSUER_MISMATCH)

    # Gate 4: audience must exactly match the configured audience. An
    # empty/missing audience can never satisfy an exact-match gate.
    allowed_audiences = policy.get("allowed_audiences")
    audience = obj.get("audience")
    if full_form:
        audience_ok = (
            isinstance(audience, str)
            and bool(audience)
            and bool(allowed_audiences)
            and audience in allowed_audiences
        )
    else:
        audience_ok = attrs["audience_ok"]
    if not audience_ok:
        add(AUDIENCE_MISMATCH)

    # Gate 5: recipient must match the configured ACS URL allowlist.
    allowed_recipients = policy.get("allowed_recipients")
    recipient = obj.get("recipient")
    if full_form:
        recipient_ok = (
            isinstance(recipient, str)
            and bool(allowed_recipients)
            and recipient in allowed_recipients
        )
    else:
        recipient_ok = attrs["recipient_ok"]
    if not recipient_ok:
        add(RECIPIENT_MISMATCH)

    # Gate 6: NotOnOrAfter bounds the current time, with clock skew.
    not_on_or_after = obj.get("not_on_or_after")
    if full_form:
        try:
            time_ok = int(not_on_or_after) + skew >= int(now_unix)
        except (TypeError, ValueError):
            time_ok = False
    else:
        time_ok = attrs["time_ok"]
    if not time_ok:
        if full_form:
            add(CLOCK_SKEW_EXCEEDED if not_on_or_after is None else EXPIRED)
        else:
            add(attrs["time_reason"])

    # Gate 7: replay protection. An assertion id may be consumed only
    # once, and only an allow may record it.
    assertion_id = obj.get("id") or _body_digest(_signed_body(obj))
    if assertion_id in store["items"]:
        add(REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[assertion_id] = {"ts": int(now_unix)}
    return report
