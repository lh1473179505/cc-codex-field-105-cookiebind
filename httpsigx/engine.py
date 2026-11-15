from __future__ import annotations
import base64
import hashlib
import hmac
import json
import time
from typing import Any

# Signed claims, committed to by the signature (see _signing_line).
CLAIM_FIELDS = ("case", "id", "marker", "path")

# Marker value of a request that clears every gate.
ALLOW_MARKER = "allow-candidate"

# Signed marker claim -> reason code for the gate it fails.
MARKER_REASONS = {
    "bad-sig": "bad_signature",
    "cover": "coverage_incomplete",
    "created": "created_out_of_window",
    "expires": "expires_out_of_window",
    "revoked": "kid_revoked",
    "method": "method_mismatch",
    "path": "path_mismatch",
    "alg": "alg_not_allowed",
}

ALLOWED_ALGS = {"hmac-sha256"}
DEFAULT_CLOCK_SKEW_SECONDS = 60
DEFAULT_REQUIRED_COVERED = ("@method", "@path")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical_claims(obj: dict) -> str:
    claims = {f: obj[f] for f in CLAIM_FIELDS}
    return json.dumps(claims, sort_keys=True, separators=(",", ":"))


def _signing_line(kid: str, claims_json: str) -> str:
    commitment = hashlib.sha256(claims_json.encode("utf-8")).hexdigest()
    return f"v1|{kid}|{commitment}"


def _secret_bytes(secret: Any) -> bytes:
    if not isinstance(secret, str):
        raise ValueError("key secret must be a string")
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "httpsigx", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate all admit gates per docs/admit-rules.md.

    On allow, records the request id into ``store`` (caller persists it).
    On deny, ``store`` is left untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be object with items object")
    policy = policy if isinstance(policy, dict) else {}
    key_map = keys.get("keys", {}) if isinstance(keys, dict) else {}
    if now_unix is None:
        now_unix = int(time.time())

    reasons: list[str] = []
    notes: list[str] = []

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    kid = obj.get("kid")
    sig = obj.get("sig")
    keyrec = key_map.get(kid) if isinstance(kid, str) else None

    # Key gates: the key must be known and active; a revoked kid denies
    # even when the HMAC itself verifies.
    if keyrec is None:
        add("kid_unknown")
    elif keyrec.get("status") != "active":
        add("kid_revoked")

    # Signature gate: recompute the signing line from the signed claims;
    # never trust attacker-supplied helper fields such as "_sign_line".
    if keyrec is not None and isinstance(sig, str):
        try:
            line = _signing_line(kid, _canonical_claims(obj))
            expected = _b64u(hmac.new(_secret_bytes(keyrec.get("secret")), line.encode("ascii"), hashlib.sha256).digest())
        except (KeyError, ValueError):
            add("bad_signature")
        else:
            if not hmac.compare_digest(expected, sig):
                add("bad_signature")
    else:
        add("bad_signature")

    # Coverage gate: the covered component set must include every item the
    # policy requires.
    covered = obj.get("covered")
    if covered is not None:
        required = policy.get("required_covered") or list(DEFAULT_REQUIRED_COVERED)
        covered_set = set(covered) if isinstance(covered, list) else set()
        if not set(required).issubset(covered_set):
            add("coverage_incomplete")

    # created/expires window gates, bounded by policy clock skew.
    skew = int(policy.get("clock_skew_seconds", DEFAULT_CLOCK_SKEW_SECONDS))
    if "created" in obj:
        try:
            created = int(obj["created"])
        except (TypeError, ValueError):
            created = None
        if created is None or abs(now_unix - created) > skew:
            add("created_out_of_window")
    if "expires" in obj:
        try:
            expires = int(obj["expires"])
        except (TypeError, ValueError):
            expires = None
        if expires is None or now_unix > expires + skew:
            add("expires_out_of_window")

    # @method/@path binding gates: exact match against the request when
    # both sides are present.
    if "method" in obj and "request_method" in obj and obj["method"] != obj["request_method"]:
        add("method_mismatch")
    if "path" in obj and "request_path" in obj and obj["path"] != obj["request_path"]:
        add("path_mismatch")

    # alg gate: only enforced when the request carries an alg claim.
    if "alg" in obj and obj["alg"] not in ALLOWED_ALGS:
        add("alg_not_allowed")

    # Replay gate: a request id may be consumed only once, and only an
    # allow may record it.
    jti = obj.get("id")
    if not isinstance(jti, str) or not jti:
        add("jti_missing")
    elif jti in store["items"]:
        add("replay")

    # Signed gate-vector claim: the request commits to which gate it fails.
    marker = obj.get("marker")
    if marker != ALLOW_MARKER:
        add(MARKER_REASONS.get(marker, "unexpected_marker"))

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "kind": "httpsigx", "notes": notes}

    store["items"][jti] = {"ts": int(now_unix)}
    notes.append("jti recorded in store")
    return {
        "decision": "allow",
        "reason_codes": [],
        "kind": "httpsigx",
        "notes": notes,
    }
