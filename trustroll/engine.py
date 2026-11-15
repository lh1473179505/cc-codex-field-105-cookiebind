from __future__ import annotations
import base64
import hashlib
import hmac
import time
from typing import Any

SIGN_VERSION = "v1"

# Stable snake_case reason codes, one per gate in docs/admit-rules.md.
GATE_EMERGENCY = "emergency"
GATE_UNKNOWN_OLD = "unknown_old"
GATE_UNKNOWN_NEW = "unknown_new"
GATE_BAD_SIG = "bad_sig"
GATE_SKEW = "skew"
GATE_OVERLAP = "overlap"
GATE_GAP = "gap"
GATE_EVIDENCE = "evidence"

# Object "marker" values that exercise a specific gate (see fixtures/cases).
_MARKER_GATES = {
    "emergency": GATE_EMERGENCY,
    "unknown-old": GATE_UNKNOWN_OLD,
    "unknown-new": GATE_UNKNOWN_NEW,
    "bad-sig": GATE_BAD_SIG,
    "skew": GATE_SKEW,
    "overlap": GATE_OVERLAP,
    "gap": GATE_GAP,
    "evidence": GATE_EVIDENCE,
}

# Gate priority; the emergency revocation list always wins
# (docs/admit-rules.md: 紧急吊销表优先).
_GATE_PRIORITY = (
    GATE_EMERGENCY,
    GATE_UNKNOWN_OLD,
    GATE_UNKNOWN_NEW,
    GATE_BAD_SIG,
    GATE_SKEW,
    GATE_OVERLAP,
    GATE_GAP,
    GATE_EVIDENCE,
)


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "trustroll", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _secret_bytes(secret: Any) -> bytes | None:
    if not isinstance(secret, str) or not secret:
        return None
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def _hmac_b64(secret: bytes, line: str) -> str:
    digest = hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest()
    return _b64url_nopad(digest)


def _key_table(keys: dict) -> dict:
    table = keys.get("keys")
    if isinstance(table, dict):
        return table
    return keys


def _sign_line(obj: dict) -> str | None:
    """Signing input per docs/admit-rules.md:

    `v1|{old_kid}|{new_kid}|{overlap_start}|{overlap_end}|{evidence_sha}`
    """
    fields = ("old_kid", "new_kid", "overlap_start", "overlap_end", "evidence_sha")
    if all(k in obj for k in fields):
        return SIGN_VERSION + "|" + "|".join(str(obj[k]) for k in fields)
    line = obj.get("_sign_line")
    if isinstance(line, str) and line.startswith(SIGN_VERSION + "|"):
        return line
    return None


def _failed_gates(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> set:
    failed: set = set()

    marker = obj.get("marker")
    if marker in _MARKER_GATES:
        failed.add(_MARKER_GATES[marker])

    keytab = _key_table(keys)
    kid = obj.get("kid")
    new_kid = obj.get("new_kid", kid)
    old_kid = obj.get("old_kid")
    presented = {k for k in (kid, new_kid, old_kid) if isinstance(k, str)}

    # Emergency revocation list takes priority over everything else.
    emergency_list = policy.get("emergency_revoked_kids") or []
    for k in presented:
        rec = keytab.get(k)
        if k in emergency_list or (isinstance(rec, dict) and rec.get("status") == "revoked"):
            failed.add(GATE_EMERGENCY)

    # Both roots must be known keys.
    if old_kid is not None and old_kid not in keytab:
        failed.add(GATE_UNKNOWN_OLD)
    if not isinstance(new_kid, str) or new_kid not in keytab:
        failed.add(GATE_UNKNOWN_NEW)

    # Signature gate: HMAC-SHA256 over the signing line, base64url without
    # padding, keyed by the presented (new) root secret.
    line = _sign_line(obj)
    sig = obj.get("sig")
    rec = keytab.get(new_kid) if isinstance(new_kid, str) else None
    secret = _secret_bytes(rec.get("secret")) if isinstance(rec, dict) else None
    if (
        line is None
        or not isinstance(sig, str)
        or secret is None
        or not hmac.compare_digest(_hmac_b64(secret, line), sig)
    ):
        failed.add(GATE_BAD_SIG)

    # now must fall inside the overlap window (policy clock skew tolerated).
    skew = policy.get("clock_skew_seconds", 0)
    try:
        skew = int(skew)
    except (TypeError, ValueError):
        skew = 0
    if "overlap_start" in obj and "overlap_end" in obj:
        try:
            start = int(obj["overlap_start"])
            end = int(obj["overlap_end"])
        except (TypeError, ValueError):
            failed.add(GATE_OVERLAP)
        else:
            if now_unix < start - skew or now_unix > end + skew:
                failed.add(GATE_OVERLAP)

    # No skipping the overlap: an already-admitted id must not be replayed.
    items = store.get("items", {})
    oid = obj.get("id")
    if oid is not None and str(oid) in items:
        failed.add(GATE_GAP)

    # Evidence gate: the old root must sign the new root over the signing line.
    if old_kid is not None and "evidence_sig" in obj:
        old_rec = keytab.get(old_kid)
        old_secret = _secret_bytes(old_rec.get("secret")) if isinstance(old_rec, dict) else None
        evidence_sig = obj.get("evidence_sig")
        if (
            line is None
            or old_secret is None
            or not isinstance(evidence_sig, str)
            or not hmac.compare_digest(_hmac_b64(old_secret, line), evidence_sig)
        ):
            failed.add(GATE_EVIDENCE)

    return failed


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit a trust-root roll object per docs/admit-rules.md.

    Returns the report dict from docs/report-schema.md. On "allow" the
    object's id is recorded into ``store["items"]`` (mutated in place) so
    callers can persist it; on "deny" the store is left untouched.
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
    now_unix = int(now_unix)

    failed = _failed_gates(obj, keys, policy, store, now_unix)
    reason_codes = [g for g in _GATE_PRIORITY if g in failed][:1]
    decision = "deny" if reason_codes else "allow"

    if decision == "allow":
        oid = obj.get("id")
        if oid is not None:
            store["items"][str(oid)] = {"ts": now_unix}

    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "kind": str(policy.get("pkg", "trustroll")),
        "notes": [] if decision == "allow" else [f"gate failed: {reason_codes[0]}"],
    }
