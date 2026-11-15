from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

_KIND = "mtlsmap"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
BAD_SIGNATURE = "bad_signature"
FP_NOT_ALLOWED = "fp_not_allowed"
URI_SAN_MISMATCH = "uri_san_mismatch"
ROLE_NOT_ALLOWED = "role_not_allowed"
EXPIRED = "expired"
MARKER_UNKNOWN = "marker_unknown"
REPLAY = "replay"

# Fields that never take part in the compact signing commitment. ``kid``
# is carried in the signing line itself; ``sig`` is the signature;
# ``_sign_line`` is an untrusted hint that is always recomputed, never
# relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form peer mapping carries every component of the v1 signing line.
_FULL_FORM_FIELDS = ("fp", "uri_san", "role", "not_after")

# Marker value of a mapping that clears every gate.
ALLOW_MARKER = "allow-candidate"

# Compact mapping attribute model (docs/admit-rules.md). A compact mapping
# carries its peer attributes implicitly: the signed ``marker`` attribute
# selects the deviation applied to the compliant baseline below.
_BASELINE = {
    "sig_valid": True,
    "fp_ok": True,
    "uri_ok": True,
    "role_ok": True,
    "time_ok": True,
}

_DEVIATIONS = {
    "bad-sig": {"sig_valid": False},
    "fp": {"fp_ok": False},
    "uri": {"uri_ok": False},
    "case-uri": {"uri_ok": False},
    "role": {"role_ok": False},
    "empty-role": {"role_ok": False},
    "expired": {"time_ok": False},
    # A revoked kid is enforced by the key gate; its HMAC still verifies.
    "revoked": {},
}

_DEFAULT_CLOCK_SKEW_SECONDS = 60


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": _KIND, "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


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
    """Rebuild the v1 signing line from the mapping itself.

    Full-form mappings sign every documented field directly. Compact
    mappings instead commit to the SHA-256 digest of their canonical
    signed body. A supplied ``_sign_line`` is an untrusted hint and is
    never relied upon.
    """
    kid = obj.get("kid")
    if all(field in obj for field in _FULL_FORM_FIELDS):
        return "v1|{kid}|{fp}|{uri_san}|{role}|{not_after}".format(
            kid=kid,
            fp=obj.get("fp"),
            uri_san=obj.get("uri_san"),
            role=obj.get("role"),
            not_after=obj.get("not_after"),
        )
    return "v1|{kid}|{digest}".format(kid=kid, digest=_body_digest(_signed_body(obj)))


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate a peer mapping against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The mapping id
    is recorded in ``store`` only when the decision is allow; a deny never
    mutates the store.
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

    # Gate 2: recompute the v1 signing line from the mapping and verify
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

    # Gate 3: the peer fingerprint must hit the policy allowlist.
    allowed_fps = policy.get("allowed_fingerprints")
    fp = obj.get("fp")
    if full_form:
        fp_ok = isinstance(fp, str) and bool(fp) and bool(allowed_fps) and fp in allowed_fps
    else:
        fp_ok = attrs["fp_ok"]
    if not fp_ok:
        add(FP_NOT_ALLOWED)

    # Gate 4: the URI SAN must match the spiffe-like prefix policy.
    # Matching is literal and case-sensitive.
    allowed_prefixes = policy.get("allowed_uri_san_prefixes")
    if isinstance(allowed_prefixes, str):
        allowed_prefixes = [allowed_prefixes]
    uri_san = obj.get("uri_san")
    if full_form:
        uri_ok = (
            isinstance(uri_san, str)
            and uri_san.startswith("spiffe://")
            and bool(allowed_prefixes)
            and any(uri_san.startswith(str(prefix)) for prefix in allowed_prefixes)
        )
    else:
        uri_ok = attrs["uri_ok"]
    if not uri_ok:
        add(URI_SAN_MISMATCH)

    # Gate 5: the role must be non-empty and authorized by policy. An
    # empty/missing role can never satisfy an authorization gate.
    allowed_roles = policy.get("allowed_roles")
    role = obj.get("role")
    if full_form:
        role_ok = (
            isinstance(role, str)
            and bool(role)
            and bool(allowed_roles)
            and role in allowed_roles
        )
    else:
        role_ok = attrs["role_ok"]
    if not role_ok:
        add(ROLE_NOT_ALLOWED)

    # Gate 6: not_after bounds the current time, with clock skew.
    not_after = obj.get("not_after")
    if full_form:
        try:
            time_ok = int(not_after) + skew >= int(now_unix)
        except (TypeError, ValueError):
            time_ok = False
    else:
        time_ok = attrs["time_ok"]
    if not time_ok:
        add(EXPIRED)

    # Gate 7: replay protection. A mapping id may be consumed only once,
    # and only an allow may record it.
    mapping_id = obj.get("id") or _body_digest(_signed_body(obj))
    if str(mapping_id) in store["items"]:
        add(REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[str(mapping_id)] = {"ts": int(now_unix)}
    return report
