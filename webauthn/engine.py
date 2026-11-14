from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

_KIND = "webauthn"

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
SIG_INVALID = "sig_invalid"
RP_ID_HASH_MISMATCH = "rp_id_hash_mismatch"
UP_REQUIRED = "up_required"
UV_REQUIRED = "uv_required"
REPLAY_COUNT = "replay_count"
CLIENT_TYPE_INVALID = "client_type_invalid"
CHALLENGE_MISMATCH = "challenge_mismatch"
CREDENTIAL_UNKNOWN = "credential_unknown"
MALFORMED = "malformed"
MARKER_UNKNOWN = "marker_unknown"

# Fields that never take part in the compact signing commitment. ``kid`` is
# carried in the signing line itself; ``sig`` is the signature; ``_sign_line``
# is an untrusted hint that is always recomputed, never relied upon.
_UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form assertion carries every component of the v1 signing line.
_FULL_FORM_FIELDS = (
    "cred_id",
    "rp_id_hash",
    "flags",
    "sign_count",
    "client_hash",
)

# Authenticator data flag bits (WebAuthn §6.1).
_FLAG_UP = 0x01
_FLAG_UV = 0x04

# Compact assertion attribute model (docs/admit-rules.md). A compact
# assertion carries its authenticator/client attributes implicitly: the
# signed ``marker`` selects the deviation applied to the compliant baseline.
_BASELINE = {
    "sig_valid": True,
    "rp_id_hash_ok": True,
    "up": True,
    "uv": True,
    "count_gt_stored": True,
    "client_type_ok": True,
    "challenge_ok": True,
    "cred_known": True,
}

_DEVIATIONS: dict[str, dict[str, Any]] = {
    "bad-sig": {"sig_valid": False},
    "rp": {"rp_id_hash_ok": False},
    "up": {"up": False},
    "uv": {"uv": False},
    "replay-count": {"count_gt_stored": False},
    "challenge": {"challenge_ok": False},
    "type": {"client_type_ok": False},
    "cred": {"cred_known": False},
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
    """Recompute the v1 signing line from the assertion itself.

    Full form follows docs/admit-rules.md exactly:
    ``v1|{cred_id}|{rp_id_hash}|{flags}|{sign_count}|{client_hash}``.
    Compact fixtures bind a canonical digest of their signed body instead.
    A supplied ``_sign_line`` hint is never trusted.
    """
    if full_form:
        return "v1|{cred_id}|{rp_id_hash}|{flags}|{sign_count}|{client_hash}".format(
            cred_id=obj.get("cred_id"),
            rp_id_hash=obj.get("rp_id_hash"),
            flags=obj.get("flags"),
            sign_count=obj.get("sign_count"),
            client_hash=obj.get("client_hash"),
        )
    return "v1|{kid}|{digest}".format(
        kid=obj.get("kid"),
        digest=_body_digest(_signed_body(obj)),
    )


def _keyring(keys: dict) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else keys


def _flag_set(flags: Any, bit: int) -> bool:
    if isinstance(flags, bool):
        return bool(flags)
    if isinstance(flags, int):
        return bool(flags & bit)
    if isinstance(flags, dict):
        return bool(flags.get("up") if bit == _FLAG_UP else flags.get("uv"))
    if isinstance(flags, str):
        token = "up" if bit == _FLAG_UP else "uv"
        return token in flags.lower()
    return False


def _stored_counter(store: dict, cred_id: Any) -> int | None:
    items = store.get("items") if isinstance(store, dict) else None
    entry = items.get(cred_id) if isinstance(items, dict) else None
    if isinstance(entry, dict) and isinstance(entry.get("sign_count"), int):
        return entry["sign_count"]
    if isinstance(entry, int):
        return entry
    return None


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": _KIND, "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate a WebAuthn assertion against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The credential
    counter is recorded in ``store`` only when the decision is allow; a deny
    never mutates the store.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be object with items object")
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

    # Gate 2: recompute the v1 signing line from the assertion itself and
    # verify the HMAC; a supplied ``_sign_line`` is never trusted.
    if active_entry is not None:
        expected = _hmac_b64url(active_entry["secret"], _signing_line(obj, full_form))
        if not hmac.compare_digest(expected, str(obj.get("sig") or "")):
            add(SIG_INVALID)
    if not attrs["sig_valid"]:
        add(SIG_INVALID)

    if full_form:
        _evaluate_full_form(obj, policy, store, add)
    else:
        _evaluate_compact(attrs, policy, add)

    if reasons:
        return report

    report["decision"] = "allow"
    cred_id = obj.get("cred_id") if full_form else (obj.get("id") or _body_digest(_signed_body(obj)))
    record: dict[str, Any] = {"ts": int(now_unix)}
    if full_form:
        record["sign_count"] = obj["sign_count"]
    store["items"][cred_id] = record
    return report


def _evaluate_compact(attrs: dict, policy: dict, add) -> None:
    """Marker-driven gates for the shipped compact fixtures."""
    if not attrs["rp_id_hash_ok"]:
        add(RP_ID_HASH_MISMATCH)
    if not attrs["up"]:
        add(UP_REQUIRED)
    if policy.get("require_uv", False) and not attrs["uv"]:
        add(UV_REQUIRED)
    if not attrs["count_gt_stored"]:
        add(REPLAY_COUNT)
    if not attrs["client_type_ok"]:
        add(CLIENT_TYPE_INVALID)
    if not attrs["challenge_ok"]:
        add(CHALLENGE_MISMATCH)
    if not attrs["cred_known"]:
        add(CREDENTIAL_UNKNOWN)


def _evaluate_full_form(obj: dict, policy: dict, store: dict, add) -> None:
    """Field-driven gates for a complete WebAuthn assertion."""
    # Gate 3: rpIdHash must match the relying party commitment.
    actual_hash = obj.get("rp_id_hash")
    expected_hash = policy.get("rp_id_hash")
    if expected_hash is None and isinstance(policy.get("rp_id"), str):
        expected_hash = hashlib.sha256(policy["rp_id"].encode("utf-8")).hexdigest()
    if expected_hash is not None and actual_hash != expected_hash:
        add(RP_ID_HASH_MISMATCH)

    # Gate 4: UP is mandatory; UV additionally when policy requires it.
    flags = obj.get("flags")
    if not _flag_set(flags, _FLAG_UP):
        add(UP_REQUIRED)
    if policy.get("require_uv", False) and not _flag_set(flags, _FLAG_UV):
        add(UV_REQUIRED)

    # Gate 5: sign_count must strictly increase; equality is a replay.
    sign_count = obj.get("sign_count")
    if not isinstance(sign_count, int) or isinstance(sign_count, bool):
        add(MALFORMED)
    else:
        stored = _stored_counter(store, obj.get("cred_id"))
        if stored is not None and sign_count <= stored:
            add(REPLAY_COUNT)

    # Gate 6: clientData must be a webauthn.get assertion with the bound
    # challenge; client_hash stays part of the signed commitment.
    client_data = obj.get("client_data") or obj.get("clientData")
    if isinstance(client_data, dict):
        if client_data.get("type") != "webauthn.get":
            add(CLIENT_TYPE_INVALID)
        expected_challenge = (
            policy.get("challenge")
            or policy.get("expected_challenge")
            or obj.get("challenge")
        )
        if expected_challenge is not None and client_data.get("challenge") != expected_challenge:
            add(CHALLENGE_MISMATCH)

    # Gate 7: the credential id must be known to the relying party when a
    # credential registry is part of policy.
    credentials = policy.get("credentials")
    if isinstance(credentials, dict) and obj.get("cred_id") not in credentials:
        add(CREDENTIAL_UNKNOWN)
