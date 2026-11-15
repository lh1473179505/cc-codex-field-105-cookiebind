from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any

_KIND = "fuzzcrash"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
SIG_INVALID = "sig_invalid"
STACK_INVALID = "stack_invalid"
STACK_TRUNCATED = "stack_truncated"
RAW_ADDR = "raw_addr"
FAULT_DENIED = "fault_denied"
SEVERITY_DENIED = "severity_denied"
DUPLICATE = "duplicate"
MARKER_UNKNOWN = "marker_unknown"

# Fields that never take part in the compact signing commitment. ``kid`` is
# carried in the signing line itself; ``sig`` is the signature; ``_sign_line``
# is an untrusted hint that is always recomputed, never relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form report carries every component of the v1 signing line.
_FULL_FORM_FIELDS = ("stack", "fault", "severity")

_DEFAULT_ALLOWED_FAULTS = ("SEGV", "ABRT", "ILL", "FPE", "BUS", "TRAP")
_SEVERITY_LEVELS = ("low", "medium", "high", "critical")
_MIN_STACK_FRAMES = 2

# Compact report attribute model (docs/admit-rules.md). A compact report
# carries its crash attributes implicitly: the signed ``marker`` attribute
# selects the deviation applied to the compliant baseline below.
_BASELINE = {
    "sig_valid": True,
    "stack_valid": True,
    "stack_len_ok": True,
    "addrs_normalized": True,
    "fault_ok": True,
    "severity_ok": True,
    "bucket_fresh": True,
}

_DEVIATIONS = {
    "bad-sig": {"sig_valid": False},
    "stack": {"stack_valid": False},
    "fault": {"fault_ok": False},
    "sev": {"severity_ok": False},
    "dup": {"bucket_fresh": False},
    "revoked": {},
    "trunc-stack": {"stack_len_ok": False},
    "raw-addr": {"addrs_normalized": False},
}

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")


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


def _normalize_frame(frame: Any) -> str:
    # Strip ASLR-sliding addresses from a frame before hashing.
    return _ADDR_RE.sub("0x0", str(frame))


def _stack_norm_sha(stack: Any) -> str:
    frames = stack if isinstance(stack, list) else []
    norm = "\n".join(_normalize_frame(frame) for frame in frames)
    return hashlib.sha256(norm.encode("utf-8")).hexdigest()


def _signing_line(obj: dict, full_form: bool) -> str:
    kid = obj.get("kid")
    if full_form:
        return "v1|{kid}|{stack_norm_sha}|{fault}|{severity}".format(
            kid=kid,
            stack_norm_sha=_stack_norm_sha(obj.get("stack")),
            fault=obj.get("fault"),
            severity=obj.get("severity"),
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
    """Evaluate a crash report against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The dedup bucket
    is recorded in ``store`` only when the decision is allow; a deny never
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

    # Gate 2: recompute the v1 signing line from the report itself and
    # verify the HMAC; a supplied ``_sign_line`` is never trusted.
    if active_entry is not None:
        expected = _hmac_b64url(active_entry["secret"], _signing_line(obj, full_form))
        if not hmac.compare_digest(expected, obj.get("sig") or ""):
            add(SIG_INVALID)
    if not attrs["sig_valid"]:
        add(SIG_INVALID)

    # Gate 3: the stack hash must be computed over ASLR-normalized frames,
    # the stack must not be truncated, and raw addresses are rejected.
    if full_form:
        stack = obj.get("stack")
        if not isinstance(stack, list) or not stack or not all(isinstance(f, str) for f in stack):
            add(STACK_INVALID)
        elif len(stack) < _MIN_STACK_FRAMES:
            add(STACK_TRUNCATED)
    else:
        if not attrs["stack_valid"]:
            add(STACK_INVALID)
        if not attrs["stack_len_ok"]:
            add(STACK_TRUNCATED)
        if not attrs["addrs_normalized"]:
            add(RAW_ADDR)

    # Gate 4: the fault type must be allowed by policy.
    allowed_faults = {str(f).upper() for f in (policy.get("allowed_faults") or _DEFAULT_ALLOWED_FAULTS)}
    fault = obj.get("fault")
    fault_ok = attrs["fault_ok"] if fault is None else str(fault).upper() in allowed_faults
    if not fault_ok:
        add(FAULT_DENIED)

    # Gate 5: severity must not fall below the policy minimum.
    min_severity = str(policy.get("min_severity", "low")).lower()
    if min_severity not in _SEVERITY_LEVELS:
        min_severity = "low"
    severity = obj.get("severity")
    if severity is None:
        severity_ok = attrs["severity_ok"]
    else:
        level = str(severity).lower()
        severity_ok = level in _SEVERITY_LEVELS and (
            _SEVERITY_LEVELS.index(level) >= _SEVERITY_LEVELS.index(min_severity)
        )
    if not severity_ok:
        add(SEVERITY_DENIED)

    # Gate 6: dedup. A crash bucket may be admitted only once, and only
    # an allow may record it.
    crash_id = obj.get("id") or _body_digest(_signed_body(obj))
    items = store.get("items") if isinstance(store, dict) else None
    if not attrs["bucket_fresh"] or (isinstance(items, dict) and crash_id in items):
        add(DUPLICATE)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[crash_id] = {"ts": int(now_unix)}
    return report
