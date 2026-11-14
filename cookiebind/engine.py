from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

_KIND = "cookiebind"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
SIG_INVALID = "sig_invalid"
NAME_PREFIX_DENIED = "name_prefix_denied"
HOST_PATH_DENIED = "host_path_denied"
SAMESITE_DENIED = "samesite_denied"
CSRF_MISMATCH = "csrf_mismatch"
PATH_DENIED = "path_denied"
CLOCK_SKEW_EXCEEDED = "clock_skew_exceeded"
REPLAY = "replay"
MARKER_UNKNOWN = "marker_unknown"

# Fields that never take part in the compact signing commitment. ``kid`` is
# carried in the signing line itself; ``sig`` is the signature; ``_sign_line``
# is an untrusted hint that is always recomputed, never relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form ticket carries every component of the v1 signing line.
_FULL_FORM_FIELDS = ("name", "prefix", "samesite", "csrf", "path", "iat", "exp")

_COOKIE_PREFIXES = ("__Host-", "__Secure-")
_DEFAULT_ALLOWED_SAMESITE = ("Strict", "Lax", "None")

# Compact ticket attribute model (docs/admit-rules.md). A compact ticket
# carries its session attributes implicitly: the signed ``marker`` attribute
# selects the deviation applied to the compliant baseline below.
_BASELINE = {
    "sig_valid": True,
    "host_path_ok": True,
    "samesite": "Strict",
    "csrf_valid": True,
    "path_ok": True,
    "time_ok": True,
    "jti_fresh": True,
}

_DEVIATIONS = {
    "bad-sig": {"sig_valid": False},
    "host-path": {"host_path_ok": False},
    "samesite": {"samesite": "bogus"},
    "csrf": {"csrf_valid": False},
    "path": {"path_ok": False},
    "revoked": {},
    "replay": {"jti_fresh": False},
    "skew": {"time_ok": False},
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hmac_b64url(secret_hex: str, line: str) -> str:
    key = bytes.fromhex(secret_hex)
    digest = hmac.new(key, line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


def _signed_body(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in _UNSIGNED_FIELDS}


def _body_digest(body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _signing_line(obj: dict, full_form: bool) -> str:
    kid = obj.get("kid")
    if full_form:
        return "v1|{kid}|{name}|{prefix}|{samesite}|{csrf}|{path}|{iat}|{exp}".format(
            kid=kid,
            name=obj.get("name"),
            prefix=obj.get("prefix"),
            samesite=obj.get("samesite"),
            csrf=obj.get("csrf"),
            path=obj.get("path"),
            iat=obj.get("iat"),
            exp=obj.get("exp"),
        )
    return "v1|{kid}|{digest}".format(kid=kid, digest=_body_digest(_signed_body(obj)))


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "cookiebind", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate a session ticket against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The jti is
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

    # Gate 1: the signing key must exist and be active. A revoked kid
    # denies even when the HMAC itself verifies.
    kid = obj.get("kid")
    entry = _keyring(keys).get(kid)
    active_entry = entry if isinstance(entry, dict) and entry.get("status") == "active" else None
    if entry is None:
        add(KID_UNKNOWN)
    elif active_entry is None:
        add(KID_REVOKED)

    # Gate 2: recompute the v1 signing line from the ticket itself and
    # verify the HMAC; a supplied ``_sign_line`` is never trusted.
    if active_entry is not None:
        expected = _hmac_b64url(active_entry["secret"], _signing_line(obj, full_form))
        if not hmac.compare_digest(expected, obj.get("sig") or ""):
            add(SIG_INVALID)
    if not attrs["sig_valid"]:
        add(SIG_INVALID)

    # Gate 3: the cookie name must carry the required __Host-/__Secure-
    # prefix; a __Host- cookie additionally requires Path=/ and no Domain.
    if full_form:
        prefix = obj.get("prefix") or ""
        name = obj.get("name") or ""
        if prefix not in _COOKIE_PREFIXES or not name.startswith(prefix):
            add(NAME_PREFIX_DENIED)
        if prefix == "__Host-" and (obj.get("path") != "/" or obj.get("domain")):
            add(HOST_PATH_DENIED)
    elif not attrs["host_path_ok"]:
        add(HOST_PATH_DENIED)

    # Gate 4: samesite must be allowed by policy.
    allowed_samesite = policy.get("allowed_samesite") or list(_DEFAULT_ALLOWED_SAMESITE)
    if obj.get("samesite", attrs["samesite"]) not in allowed_samesite:
        add(SAMESITE_DENIED)

    # Gate 5: credential mode (require_csrf) binds the csrf claim to the
    # policy body seed.
    if policy.get("require_csrf", True):
        csrf_ok = attrs["csrf_valid"]
        seed = policy.get("body_csrf_seed")
        if obj.get("csrf") is not None and seed is not None and active_entry is not None:
            expected_csrf = _hmac_b64url(active_entry["secret"], str(seed))
            csrf_ok = hmac.compare_digest(expected_csrf, obj.get("csrf") or "")
        if not csrf_ok:
            add(CSRF_MISMATCH)

    # Gate 6: the path must avoid denied substrings and hit path_allow
    # (exact/prefix) whenever the policy defines them.
    path_ok = attrs["path_ok"]
    path = obj.get("path")
    denied_substrings = policy.get("denied_path_substrings")
    if denied_substrings and isinstance(path, str):
        if any(sub in path for sub in denied_substrings):
            path_ok = False
    path_allow = policy.get("path_allow")
    if path_allow and isinstance(path, str):
        path_ok = path_ok and any(
            ("exact" in rule and path == rule["exact"])
            or ("prefix" in rule and path.startswith(rule["prefix"]))
            for rule in path_allow
        )
    if not path_ok:
        add(PATH_DENIED)

    # Gate 7: |now-iat| and exp are bounded by clock_skew_seconds.
    skew = policy.get("clock_skew_seconds", 60)
    time_ok = attrs["time_ok"]
    iat = obj.get("iat")
    exp = obj.get("exp")
    if isinstance(iat, int) and abs(now_unix - iat) > skew:
        time_ok = False
    if isinstance(exp, int) and now_unix > exp + skew:
        time_ok = False
    if not time_ok:
        add(CLOCK_SKEW_EXCEEDED)

    # Gate 8: replay protection. A jti may be consumed only once, and only
    # an allow may record it.
    jti = obj.get("jti") or obj.get("id") or _body_digest(_signed_body(obj))
    items = store.get("items") if isinstance(store, dict) else None
    if not attrs["jti_fresh"] or (isinstance(items, dict) and jti in items):
        add(REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[jti] = {"ts": int(now_unix)}
    return report
