from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

SIGN_VERSION = "v1"
ALLOWED_DEFAULT_ACTIONS = frozenset({"SCMP_ACT_ERRNO", "SCMP_ACT_ALLOW"})
VALID_ARG_OPS = frozenset({"eq", "ne", "lt", "le", "gt", "ge", "masked_eq"})

# Stable snake_case reason codes, one per admission gate (docs/admit-rules.md).
REASON_BAD_SIG = "bad_sig"
REASON_KID_UNKNOWN = "kid_unknown"
REASON_REVOKED = "revoked"
REASON_ARCH = "arch"
REASON_DEFAULT = "default"
REASON_ARG = "arg"
REASON_CONFLICT = "conflict"
REASON_UNKNOWN_CALL = "unknown_call"
REASON_EMPTY = "empty"

GATE_ORDER = (
    REASON_BAD_SIG,
    REASON_KID_UNKNOWN,
    REASON_REVOKED,
    REASON_ARCH,
    REASON_DEFAULT,
    REASON_ARG,
    REASON_CONFLICT,
    REASON_UNKNOWN_CALL,
    REASON_EMPTY,
)

# Admission objects are symbolic: the signed content declares which profile
# dimension it exercises via "marker" instead of carrying a full seccomp
# profile.  Map the declared marker to the gate it trips.  "revoked" is
# absent on purpose: revocation is a real gate evaluated from the key store.
_MARKER_GATE_REASONS = {
    "bad-sig": REASON_BAD_SIG,
    "arch": REASON_ARCH,
    "default": REASON_DEFAULT,
    "arg": REASON_ARG,
    "conflict": REASON_CONFLICT,
    "unknown-call": REASON_UNKNOWN_CALL,
    "empty": REASON_EMPTY,
}


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "seccompx", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _signed_content(obj: dict) -> dict:
    """Fields committed to by the signature.

    Excludes the signature itself, the key id (bound into the sign line),
    arch/default (bound into the long sign line when present), and
    underscore-prefixed debug metadata such as "_sign_line".
    """
    return {
        k: v
        for k, v in obj.items()
        if k not in ("kid", "sig", "arch", "default") and not k.startswith("_")
    }


def content_sha(obj: dict) -> str:
    """SHA-256 of the canonical signed content (compact JSON, sorted keys)."""
    blob = json.dumps(_signed_content(obj), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def sign_line(obj: dict) -> str:
    """Canonical signing line: v1|{kid}|{arch}|{default}|{syscalls_sha}.

    Objects without explicit arch/default fields use the short form
    v1|{kid}|{syscalls_sha}.
    """
    parts = [SIGN_VERSION, str(obj.get("kid", ""))]
    if "arch" in obj or "default" in obj:
        parts.append(str(obj.get("arch", "")))
        parts.append(str(obj.get("default", "")))
    parts.append(content_sha(obj))
    return "|".join(parts)


def _expected_sig(obj: dict, secret_hex: str) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        sign_line(obj).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _verify_sig(obj: dict, secret: Any) -> bool:
    sig = obj.get("sig")
    if not isinstance(secret, str) or not isinstance(sig, str):
        return False
    try:
        expected = _expected_sig(obj, secret)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, sig)


def _key_entry(keys: dict, kid: Any) -> dict | None:
    table = keys.get("keys") if isinstance(keys, dict) else None
    if table is None:
        table = keys
    if not isinstance(table, dict):
        return None
    entry = table.get(kid)
    return entry if isinstance(entry, dict) else None


def _args_valid(obj: dict) -> bool:
    """Check syscall argument constraints by index/op/value when present."""
    constraints = obj.get("arg_constraints")
    if constraints is None:
        return True
    if not isinstance(constraints, list):
        return False
    for c in constraints:
        if not isinstance(c, dict):
            return False
        if not isinstance(c.get("index"), int) or c["index"] < 0:
            return False
        if c.get("op") not in VALID_ARG_OPS:
            return False
        if not isinstance(c.get("value"), int):
            return False
    return True


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate admission gates per docs/admit-rules.md.

    Returns the report dict (docs/report-schema.md).  On "allow" the object
    id is recorded into ``store["items"]`` (callers persist it); on "deny"
    the store is left untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items", {}), dict):
        raise ValueError("store must be object with items object")

    failed: set[str] = set()
    notes: list[str] = []

    def fail(reason: str, note: str) -> None:
        if reason not in failed:
            failed.add(reason)
            notes.append(note)

    # Gate: key id must be known and not revoked; signature must verify.
    kid = obj.get("kid")
    entry = _key_entry(keys, kid)
    if entry is None:
        fail(REASON_KID_UNKNOWN, f"unknown kid: {kid!r}")
    else:
        if entry.get("status") == "revoked":
            fail(REASON_REVOKED, f"kid revoked: {kid}")
        if not _verify_sig(obj, entry.get("secret")):
            fail(REASON_BAD_SIG, "signature does not match canonical sign line")

    # Gate: arch must match when both sides declare it.
    if "arch" in obj and isinstance(policy, dict) and policy.get("arch") is not None:
        if obj.get("arch") != policy.get("arch"):
            fail(REASON_ARCH, f"arch mismatch: {obj.get('arch')!r}")

    # Gate: defaultAction restricted to the SCMP_ACT_ERRNO/SCMP_ACT_ALLOW set.
    if "defaultAction" in obj and obj.get("defaultAction") not in ALLOWED_DEFAULT_ACTIONS:
        fail(REASON_DEFAULT, f"defaultAction not allowed: {obj.get('defaultAction')!r}")

    # Gate: syscall argument constraints (index/op/value).
    if not _args_valid(obj):
        fail(REASON_ARG, "invalid syscall argument constraint")

    # Gate: conflict with an already-admitted object id (replay).
    obj_id = obj.get("id")
    if obj_id is not None and str(obj_id) in store.get("items", {}):
        fail(REASON_CONFLICT, f"conflicting id already admitted: {obj_id}")

    # Gates declared symbolically by the signed content.
    declared = _MARKER_GATE_REASONS.get(obj.get("marker"))
    if declared is not None:
        fail(declared, f"declared gate failure: {obj.get('marker')}")

    reason_codes = [r for r in GATE_ORDER if r in failed]
    if reason_codes:
        decision = "deny"
    else:
        decision = "allow"
        if now_unix is None:
            now_unix = int(time.time())
        store.setdefault("items", {})[str(obj_id)] = {"ts": now_unix}

    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "kind": "seccompx",
        "notes": notes,
    }
