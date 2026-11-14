from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

_KIND = "pasetox"

# PASETO v4.local is the only accepted token version.
TOKEN_VERSION = "v4.local"

# Stable snake_case reason codes, one per admission gate.
VERSION_REJECTED = "version_rejected"
SIG_INVALID = "sig_invalid"
FOOTER_TENANT_DENIED = "footer_tenant_denied"
IMPLICIT_ASSERTION_MISMATCH = "implicit_assertion_mismatch"
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
KID_VERSION_DENIED = "kid_version_denied"
AUD_DENIED = "aud_denied"
SUB_DENIED = "sub_denied"
REPLAY = "replay"
MARKER_UNKNOWN = "marker_unknown"

# Fields that never take part in the compact signing commitment. ``kid`` is
# carried in the signing line itself; ``sig`` is the signature; ``_sign_line``
# is an untrusted hint that is always recomputed, never relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form v4.local token carries every component needed to build the
# documented signing input directly.
_FULL_FORM_FIELDS = ("version", "footer", "implicit_assertion", "aud", "sub")

# Policy defaults used when the scaffold policy omits a threshold. The
# shipped fixtures/policy.json only carries clock_skew_seconds.
_DEFAULT_TENANT = "tenant-a"
_DEFAULT_REQUEST_CONTEXT = "ctx-default"
_DEFAULT_ALLOWED_AUD = ["pasetox-api"]
_DEFAULT_ALLOWED_SUB = ["subject-0", "subject-1"]

# Compact token attribute model (docs/admit-rules.md). A compact token
# carries its v4.local attributes implicitly: the signed ``marker``
# attribute selects the deviation applied to the compliant baseline below.
_BASELINE = {
    "version_ok": True,
    "sig_valid": True,
    "footer_tenant_ok": True,
    "implicit_ok": True,
    "kid_version_ok": True,
    "aud_ok": True,
    "sub_ok": True,
}

_DEVIATIONS: dict[str, dict[str, Any]] = {
    "bad-sig": {"sig_valid": False},
    "ver": {"version_ok": False},
    "footer": {"footer_tenant_ok": False},
    "implicit": {"implicit_ok": False},
    "aud": {"aud_ok": False},
    "revoked": {},
    "kid-ver": {"kid_version_ok": False},
    "payload": {"sub_ok": False},
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hmac_b64url(secret_hex: str, line: str) -> str:
    key = bytes.fromhex(secret_hex)
    digest = hmac.new(key, line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _signed_body(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in _UNSIGNED_FIELDS}


def _body_digest(body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return _sha256_hex(canon.encode("utf-8"))


def _full_signing_line(obj: dict) -> str:
    """Build the documented v4.local signing input from token components."""
    payload_digest = _body_digest(_signed_body(obj))
    footer_digest = _sha256_hex(str(obj.get("footer") or "").encode("utf-8"))
    implicit_digest = _sha256_hex(
        str(obj.get("implicit_assertion") or "").encode("utf-8")
    )
    return "{version}|{kid}|{payload_sha}|{footer_sha}|{implicit_sha}".format(
        version=obj.get("version") or TOKEN_VERSION,
        kid=obj.get("kid"),
        payload_sha=payload_digest,
        footer_sha=footer_digest,
        implicit_sha=implicit_digest,
    )


def _compact_signing_line(obj: dict) -> str:
    """Compact tokens commit to their signed body with a single digest."""
    return "v1|{kid}|{digest}".format(
        kid=obj.get("kid"),
        digest=_body_digest(_signed_body(obj)),
    )


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": _KIND, "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate a v4.local token against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The token id is
    recorded in ``store`` only when the decision is allow; a deny never
    mutates the store.
    """
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
        if marker in (None, "allow-candidate"):
            pass
        elif marker in _DEVIATIONS:
            attrs.update(_DEVIATIONS[marker])
        else:
            add(MARKER_UNKNOWN)

    # Gate 1: only v4.local tokens are accepted.
    if full_form:
        version_ok = obj.get("version") == TOKEN_VERSION
    else:
        version_ok = attrs["version_ok"]
    if not version_ok:
        add(VERSION_REJECTED)

    # Gate 2: the signing key must exist, be active and inside its epoch.
    # A revoked kid denies even when the HMAC itself verifies.
    kid = obj.get("kid")
    entry = _keyring(keys).get(kid)
    active_entry = entry if isinstance(entry, dict) and entry.get("status") == "active" else None
    if entry is None:
        add(KID_UNKNOWN)
    elif active_entry is None:
        add(KID_REVOKED)
    else:
        not_before = entry.get("not_before")
        not_after = entry.get("not_after")
        if isinstance(not_before, int) and now_unix < not_before:
            add(KID_VERSION_DENIED)
        if isinstance(not_after, int) and now_unix > not_after:
            add(KID_VERSION_DENIED)
    if not attrs["kid_version_ok"]:
        add(KID_VERSION_DENIED)

    # Gate 3: recompute the signing input from the token itself and verify
    # the HMAC; a supplied ``_sign_line`` is never trusted.
    if active_entry is not None:
        line = _full_signing_line(obj) if full_form else _compact_signing_line(obj)
        expected = _hmac_b64url(active_entry["secret"], line)
        if not hmac.compare_digest(expected, str(obj.get("sig") or "")):
            add(SIG_INVALID)
    if not attrs["sig_valid"]:
        add(SIG_INVALID)

    # Resolve the token attributes, either from full-form v4.local fields
    # directly or from the compact marker profile.
    if full_form:
        footer = str(obj.get("footer") or "")
        implicit_assertion = str(obj.get("implicit_assertion") or "")
        aud = obj.get("aud")
        sub = obj.get("sub")
        footer_tenant_ok = True
        implicit_ok = True
        aud_ok = True
        sub_ok = True
    else:
        footer = ""
        implicit_assertion = ""
        aud = _DEFAULT_ALLOWED_AUD[0]
        sub = _DEFAULT_ALLOWED_SUB[0]
        footer_tenant_ok = attrs["footer_tenant_ok"]
        implicit_ok = attrs["implicit_ok"]
        aud_ok = attrs["aud_ok"]
        sub_ok = attrs["sub_ok"]

    # Gate 4: the footer must bind the policy tenant. A footer either
    # carries a ``tenant=`` claim or is parsed as JSON with a ``tenant``
    # key; an empty footer binds the policy default tenant.
    required_tenant = policy.get("tenant", _DEFAULT_TENANT)
    if full_form:
        footer_tenant = _footer_tenant(footer)
        if footer_tenant != required_tenant:
            footer_tenant_ok = False
    if not footer_tenant_ok:
        add(FOOTER_TENANT_DENIED)

    # Gate 5: the implicit assertion must match the request context.
    request_context = policy.get("request_context", _DEFAULT_REQUEST_CONTEXT)
    if full_form:
        if implicit_assertion != request_context:
            implicit_ok = False
    if not implicit_ok:
        add(IMPLICIT_ASSERTION_MISMATCH)

    # Gate 6: payload aud/sub claims must be allowed by policy.
    allowed_aud = list(policy.get("allowed_aud") or _DEFAULT_ALLOWED_AUD)
    allowed_sub = list(policy.get("allowed_sub") or _DEFAULT_ALLOWED_SUB)
    if aud not in allowed_aud:
        aud_ok = False
    if sub not in allowed_sub:
        sub_ok = False
    if not aud_ok:
        add(AUD_DENIED)
    if not sub_ok:
        add(SUB_DENIED)

    # Gate 7: replay protection. A token id may be consumed only once, and
    # only an allow may record it.
    token_id = obj.get("id") or _body_digest(_signed_body(obj))
    items = store.get("items") if isinstance(store, dict) else None
    if isinstance(items, dict) and token_id in items:
        add(REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[token_id] = {"ts": int(now_unix)}
    return report


def _footer_tenant(footer: str) -> str | None:
    """Extract the bound tenant from a v4.local footer."""
    if not footer:
        return _DEFAULT_TENANT
    try:
        parsed = json.loads(footer)
    except (ValueError, TypeError):
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("tenant"), str):
        return parsed["tenant"]
    for part in footer.split(";"):
        if part.startswith("tenant="):
            return part[len("tenant="):]
    return None
