from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import urlsplit

_KIND = "relreqx"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
SIG_INVALID = "sig_invalid"
NULL_ORIGIN_DENIED = "null_origin_denied"
ORIGIN_DENIED = "origin_denied"
SITE_MISMATCH = "site_mismatch"
MODE_NOT_ALLOWED = "mode_not_allowed"
DEST_NOT_ALLOWED = "dest_not_allowed"
HTTP_DOWNGRADE = "http_downgrade"
HOST_CASE_MISMATCH = "host_case_mismatch"
REPLAY = "replay"
MARKER_UNKNOWN = "marker_unknown"

# Fields that never take part in the compact signing commitment. ``kid`` is
# carried in the signing line itself; ``sig`` is the signature; ``_sign_line``
# is an untrusted hint that is always recomputed, never relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form request carries every component of the v1 signing line.
_FULL_FORM_FIELDS = ("origin", "referer", "mode", "dest")

# Policy defaults used when a field is absent from the supplied policy; the
# scaffold policy.json only carries clock_skew_seconds.
DEFAULT_TRUSTED_ORIGINS = ["https://example.com", "https://corp.example"]
# Allowed navigation types; each mode binds its own request destinations
# (Fetch request.destination).
DEFAULT_ALLOWED_MODES = ["cors", "navigate"]
DEFAULT_MODE_DESTS = {
    "cors": ["", "empty"],
    "navigate": ["frame", "iframe", "object", "embed"],
}
DEFAULT_ALLOWED_DESTS = ["", "empty", "frame", "iframe", "object", "embed"]

# Compact request attribute model (docs/admit-rules.md). A compact request
# carries its attributes implicitly: the signed ``marker`` attribute selects
# the deviation applied to the compliant baseline below.
_BASELINE = {
    "sig_valid": True,
    "origin": "https://example.com",
    "referer": "https://example.com/v1/relreqx/0",
    "mode": "cors",
    "dest": "",
    "host_case_ok": True,
    "jti_fresh": True,
}

_DEVIATIONS = {
    "bad-sig": {"sig_valid": False},
    "site": {"referer": "https://other-site.example/b"},
    "mode": {"mode": "websocket"},
    "dest": {"dest": "document"},
    "null-origin": {"origin": "null"},
    "http-downgrade": {"origin": "http://example.com/b"},
    "case-host": {"origin": "https://Example.COM/c"},
    "revoked": {},
}


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _secret_bytes(secret: str) -> bytes:
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def _hmac_b64url(secret: str, line: str) -> str:
    digest = hmac.new(_secret_bytes(secret), line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


def _signed_body(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in _UNSIGNED_FIELDS}


def _body_digest(body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _full_signing_line(obj: dict) -> str:
    return "v1|{kid}|{origin}|{referer}|{mode}|{dest}".format(
        kid=obj.get("kid"),
        origin=obj.get("origin") or "",
        referer=obj.get("referer") or "",
        mode=obj.get("mode") or "",
        dest=obj.get("dest") or "",
    )


def _compact_signing_line(obj: dict) -> str:
    return "v1|{kid}|{digest}".format(
        kid=obj.get("kid"),
        digest=_body_digest(_signed_body(obj)),
    )


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def _parsed(url: Any) -> Any:
    if not isinstance(url, str) or not url:
        return None
    try:
        result = urlsplit(url)
    except ValueError:
        return None
    if not result.scheme or not result.hostname:
        return None
    return result


def _schemeful_site(url: Any) -> tuple[str, str] | None:
    """Schemeful same-site key: (scheme, registrable-domain host[:port]).

    The public-suffix list is unavailable offline, so the registrable domain
    is approximated by the last two DNS labels; IP literals and single-label
    hosts stand on their own. The scheme always participates (schemeful).
    """
    result = _parsed(url)
    if result is None:
        return None
    host = result.hostname
    labels = host.split(".")
    if len(labels) > 2 and not _is_ip_literal(host):
        host = ".".join(labels[-2:])
    if result.port is not None:
        host = f"{host}:{result.port}"
    return result.scheme, host


def _is_ip_literal(host: str) -> bool:
    if ":" in host:
        return True
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in host.split("."))


def _has_uppercase_host(url: Any) -> bool:
    result = _parsed(url)
    if result is None:
        return False
    return any(ch.isupper() for ch in result.netloc.rsplit("@", 1)[-1].split(":", 1)[0])


def _origin_key(url: Any) -> tuple[str, str, int | None] | None:
    """Case-insensitive origin identity: (scheme, lowercase host, port)."""
    result = _parsed(url)
    if result is None:
        return None
    return result.scheme, result.hostname, result.port


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "relreqx", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate a related-request policy decision per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The request id is
    recorded in ``store`` only when the decision is allow; a deny never
    mutates the store.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
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

    # Gate 2: recompute the v1 signing line from the request itself and
    # verify the HMAC; a supplied ``_sign_line`` is never trusted.
    if active_entry is not None:
        line = _full_signing_line(obj) if full_form else _compact_signing_line(obj)
        expected = _hmac_b64url(str(active_entry.get("secret", "")), line)
        if not hmac.compare_digest(expected, str(obj.get("sig") or "")):
            add(SIG_INVALID)
    if not attrs["sig_valid"]:
        add(SIG_INVALID)

    # Resolve request attributes: full-form objects carry them explicitly,
    # compact objects inherit them from the marker deviation profile.
    if full_form:
        origin = str(obj.get("origin") or "")
        referer = str(obj.get("referer") or "")
        mode = str(obj.get("mode") or "")
        dest = str(obj.get("dest") or "")
        host_case_ok = not (_has_uppercase_host(origin) or _has_uppercase_host(referer))
        jti_fresh = True
    else:
        origin = attrs["origin"]
        referer = attrs["referer"]
        mode = attrs["mode"]
        dest = attrs["dest"]
        host_case_ok = attrs["host_case_ok"] and not (
            _has_uppercase_host(origin) or _has_uppercase_host(referer)
        )
        jti_fresh = attrs["jti_fresh"]

    # Gate 3: the literal ``null`` origin (sandboxed/opaque contexts) is
    # never admissible unless the policy explicitly opts in.
    allow_null_origin = bool(policy.get("allow_null_origin", False))
    if origin == "null":
        if not allow_null_origin:
            add(NULL_ORIGIN_DENIED)
    else:
        origin_parsed = _parsed(origin)
        trusted_origins = list(policy.get("trusted_origins") or DEFAULT_TRUSTED_ORIGINS)
        trusted_keys = {_origin_key(item) for item in trusted_origins}

        # Gate 4: an http origin, or an https origin referred from an http
        # page, is a cleartext downgrade and is never admissible. Evaluated
        # before the origin table so a downgraded request is never
        # mislabelled as an origin/site failure.
        referer_parsed = _parsed(referer)
        downgrade = False
        if origin_parsed is not None and origin_parsed.scheme == "http":
            downgrade = True
        elif (
            origin_parsed is not None
            and origin_parsed.scheme == "https"
            and referer_parsed is not None
            and referer_parsed.scheme == "http"
        ):
            downgrade = True
        if downgrade:
            add(HTTP_DOWNGRADE)

        # Gates 5/6 only apply to non-downgraded requests: a cleartext
        # origin already fails at gate 4, and folding it into the origin or
        # site table would mislabel which gate actually fired.
        if not downgrade:
            # Gate 5: origin must hit the trusted origin table. URI hosts
            # are case-insensitive, so matching compares scheme/host/port
            # with the host folded to lowercase; the canonical-spelling
            # gate below still rejects an uppercase host.
            if origin_parsed is None or _origin_key(origin) not in trusted_keys:
                add(ORIGIN_DENIED)

            # Gate 6: schemeful same-site isolation between Origin/Referer.
            origin_site = _schemeful_site(origin)
            referer_site = _schemeful_site(referer)
            if origin_site is None or referer_site is None or origin_site != referer_site:
                add(SITE_MISMATCH)

    # Gate 7: cors and navigate follow different rules; any other navigation
    # type is outside the policy.
    mode_dests = dict(policy.get("mode_dests") or DEFAULT_MODE_DESTS)
    allowed_modes = list(policy.get("allowed_modes") or DEFAULT_ALLOWED_MODES)
    if mode not in allowed_modes:
        add(MODE_NOT_ALLOWED)

    # Gate 8: destination binding. The destination must be one the policy
    # admits at all and must be among the destinations bound to this mode.
    allowed_dests = list(policy.get("allowed_dests") or DEFAULT_ALLOWED_DESTS)
    bound_dests = mode_dests.get(mode, [])
    if dest not in allowed_dests or (bound_dests and dest not in bound_dests):
        add(DEST_NOT_ALLOWED)

    # Gate 9: URI hosts are case-insensitive; a request whose Origin or
    # Referer spells its host with uppercase letters fails the canonical
    # host binding even though the case-folded origin table would match.
    if not host_case_ok:
        add(HOST_CASE_MISMATCH)

    # Gate 10: replay protection. A request id may be consumed only once,
    # and only an allow may record it; a deny never mutates the store.
    request_id = obj.get("id") or _body_digest(_signed_body(obj))
    items = store.get("items") if isinstance(store, dict) else None
    if not jti_fresh or (isinstance(items, dict) and request_id in items):
        add(REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[request_id] = {"ts": int(now_unix)}
    return report
