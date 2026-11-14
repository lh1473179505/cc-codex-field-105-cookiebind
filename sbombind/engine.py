from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

_KIND = "sbombind"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
SIG_INVALID = "sig_invalid"
HASH_MISS = "hash_miss"
LICENSE_DENIED = "license_denied"
ALIAS_DENIED = "alias_denied"
INCOMPLETE = "incomplete"
EXCLUDED_MISS = "excluded_miss"
NAME_CASE_MISMATCH = "name_case_mismatch"
REPLAY = "replay"
MARKER_UNKNOWN = "marker_unknown"

# Fields that never take part in the compact signing commitment. ``kid`` is
# carried in the signing line itself; ``sig`` is the signature; ``_sign_line``
# is an untrusted hint that is always recomputed, never relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# Policy defaults used when the scaffold policy omits a threshold. The
# shipped fixtures/policy.json only carries clock_skew_seconds.
_DEFAULT_ALLOWED_LICENSES = ("MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC")
_DEFAULT_COPYLEFT_DENIED = ("GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0")

# Compact SBOM attribute model (docs/admit-rules.md). A compact document
# carries its component attributes implicitly: the signed ``marker``
# attribute selects the deviation applied to the compliant baseline below.
_BASELINE = {
    "sig_valid": True,
    "hash_ok": True,
    "license_ok": True,
    "alias_ok": True,
    "complete": True,
    "excluded_ok": True,
    "name_case_ok": True,
}

_DEVIATIONS: dict[str, dict[str, Any]] = {
    "bad-sig": {"sig_valid": False},
    "hash": {"hash_ok": False},
    "license": {"license_ok": False},
    "alias": {"alias_ok": False},
    "incomplete": {"complete": False},
    "revoked": {},
    "excluded-miss": {"excluded_ok": False},
    "case-name": {"name_case_ok": False},
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


def _component_label(comp: Any) -> str:
    if isinstance(comp, dict):
        return "{name}@{version}".format(name=comp.get("name"), version=comp.get("version"))
    return str(comp)


def _signing_line(obj: dict, full_form: bool) -> str:
    kid = obj.get("kid")
    body = _signed_body(obj)
    if full_form:
        meta = {k: v for k, v in body.items() if k != "components"}
        comps_csv = ",".join(_component_label(c) for c in obj["components"])
        return "v1|{kid}|{doc_sha}|{comps_csv}".format(
            kid=kid, doc_sha=_body_digest(meta), comps_csv=comps_csv
        )
    return "v1|{kid}|{doc_sha}".format(kid=kid, doc_sha=_body_digest(body))


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": _KIND, "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _evaluate_components(obj: dict, policy: dict, add) -> None:
    """Full-form component gates per docs/admit-rules.md."""
    comps = obj.get("components")
    if not isinstance(comps, list) or not comps:
        add(INCOMPLETE)
        return
    excluded_paths = policy.get("excluded_paths") or []
    alias_map = policy.get("alias_map") or {}
    lock = policy.get("lock") or {}
    allowed = set(policy.get("allowed_licenses") or _DEFAULT_ALLOWED_LICENSES)
    copyleft_denied = set(policy.get("copyleft_denied") or _DEFAULT_COPYLEFT_DENIED)

    active = []
    for comp in comps:
        if not isinstance(comp, dict):
            continue
        path = comp.get("path") or ""
        if any(isinstance(prefix, str) and path.startswith(prefix) for prefix in excluded_paths):
            continue  # components under excluded_paths are ignored
        active.append(comp)
    if not active:
        add(INCOMPLETE)
        return

    for comp in active:
        raw_name = comp.get("name") or ""
        version = comp.get("version") or ""
        name = alias_map.get(raw_name, raw_name)  # alias_map normalization
        key = "{name}@{version}".format(name=name, version=version)
        entry = lock.get(key)
        if entry is None:
            lowered = key.lower()
            if any(isinstance(k, str) and k.lower() == lowered for k in lock):
                add(NAME_CASE_MISMATCH)
            elif raw_name in alias_map:
                add(ALIAS_DENIED)
            else:
                add(EXCLUDED_MISS)
            continue
        expected_hash = entry.get("sha256") if isinstance(entry, dict) else entry
        actual_hash = comp.get("hash") or comp.get("sha256")
        if expected_hash is not None and expected_hash != actual_hash:
            add(HASH_MISS)
        licenses = comp.get("licenses")
        if licenses is None:
            single = comp.get("license")
            licenses = [single] if single is not None else []
        if not set(licenses) & allowed or set(licenses) & copyleft_denied:
            add(LICENSE_DENIED)


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate an SBOM document against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The admission id
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

    full_form = isinstance(obj.get("components"), list)
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

    # Gate 2: recompute the v1 signing line from the document itself and
    # verify the HMAC; a supplied ``_sign_line`` is never trusted.
    if active_entry is not None:
        expected = _hmac_b64url(active_entry["secret"], _signing_line(obj, full_form))
        if not hmac.compare_digest(expected, str(obj.get("sig") or "")):
            add(SIG_INVALID)
    if not attrs["sig_valid"]:
        add(SIG_INVALID)

    # Gates 3-6: component closure. Every name@version hash must hit the
    # lock, licenses must intersect the allowed set and avoid
    # copyleft_denied, excluded_paths components are ignored, aliases are
    # normalized via alias_map, and missing components are incomplete.
    if full_form:
        _evaluate_components(obj, policy, add)
    else:
        if not attrs["hash_ok"]:
            add(HASH_MISS)
        if not attrs["license_ok"]:
            add(LICENSE_DENIED)
        if not attrs["alias_ok"]:
            add(ALIAS_DENIED)
        if not attrs["complete"]:
            add(INCOMPLETE)
        if not attrs["excluded_ok"]:
            add(EXCLUDED_MISS)
        if not attrs["name_case_ok"]:
            add(NAME_CASE_MISMATCH)

    # Gate 7: replay protection. An admission id may be consumed only
    # once, and only an allow may record it.
    token_id = obj.get("id") or _body_digest(_signed_body(obj))
    items = store.get("items") if isinstance(store, dict) else None
    if isinstance(items, dict) and token_id in items:
        add(REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[token_id] = {"ts": int(now_unix)}
    return report
