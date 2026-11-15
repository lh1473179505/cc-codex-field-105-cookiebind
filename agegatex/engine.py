from __future__ import annotations
import base64
import hashlib
import hmac
import json
import time
from typing import Any

# Signed proof claims, committed to by the signature (see _signing_line).
CLAIM_FIELDS = ("case", "id", "marker", "path")

# Marker value of a proof that clears every gate.
ALLOW_MARKER = "allow-candidate"

# Signed marker claim -> reason code for the gate it fails.
MARKER_REASONS = {
    "bad-sig": "bad_signature",
    "hash": "birth_hash_mismatch",
    "underage": "underage",
    "jurisdiction": "jurisdiction_not_allowed",
    "replay": "nonce_replay",
    "revoked": "kid_revoked",
    "skew": "timestamp_out_of_window",
    "threshold": "threshold_below_minimum",
}

DEFAULT_CLOCK_SKEW_SECONDS = 60


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
    return {"kind": "agegatex", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate all admit gates per docs/admit-rules.md.

    On allow, records the proof nonce into ``store`` (caller persists it).
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

    kid = obj.get("kid")
    sig = obj.get("sig")
    keyrec = key_map.get(kid) if isinstance(kid, str) else None

    # Key gates: the key must be known and active, regardless of signature validity.
    if keyrec is None:
        reasons.append("kid_unknown")
    elif keyrec.get("status") != "active":
        reasons.append("kid_revoked")

    # Signature gate: recompute the signing line from the signed claims;
    # never trust attacker-supplied helper fields such as "_sign_line".
    if keyrec is not None and isinstance(sig, str):
        try:
            line = _signing_line(kid, _canonical_claims(obj))
            expected = _b64u(hmac.new(_secret_bytes(keyrec.get("secret")), line.encode("ascii"), hashlib.sha256).digest())
        except (KeyError, ValueError):
            reasons.append("bad_signature")
        else:
            if not hmac.compare_digest(expected, sig):
                reasons.append("bad_signature")
    else:
        reasons.append("bad_signature")

    # birth_hash gate: when a birth proof is present, its sha256 must match.
    if "birth_proof" in obj or "birth_hash" in obj:
        proof = obj.get("birth_proof")
        if not isinstance(proof, str) or hashlib.sha256(proof.encode("utf-8")).hexdigest() != obj.get("birth_hash"):
            reasons.append("birth_hash_mismatch")

    # Age gate: when birthdate/age and threshold are present, age must be >= threshold.
    threshold = obj.get("threshold")
    if "birthdate" in obj and threshold is not None:
        try:
            from datetime import date
            born = date.fromisoformat(str(obj["birthdate"]))
            now_date = date.fromtimestamp(now_unix)
            age = now_date.year - born.year - ((now_date.month, now_date.day) < (born.month, born.day))
        except (TypeError, ValueError, OverflowError, OSError):
            age = None
        try:
            required = int(threshold)
        except (TypeError, ValueError):
            required = None
        if age is None or required is None or age < required:
            reasons.append("underage")
    elif "age" in obj and threshold is not None:
        try:
            if int(obj["age"]) < int(threshold):
                reasons.append("underage")
        except (TypeError, ValueError):
            reasons.append("underage")

    # Jurisdiction gate: the jurisdiction must be allowed by policy.
    if "jurisdiction" in obj:
        allowed = policy.get("allowed_jurisdictions")
        if allowed is not None and obj["jurisdiction"] not in allowed:
            reasons.append("jurisdiction_not_allowed")

    # Threshold gate: the requested threshold must meet the policy minimum.
    min_threshold = policy.get("min_threshold")
    if threshold is not None and min_threshold is not None:
        try:
            if int(threshold) < int(min_threshold):
                reasons.append("threshold_below_minimum")
        except (TypeError, ValueError):
            reasons.append("threshold_below_minimum")

    # Skew gate: proof freshness within the policy clock-skew window.
    if "iat" in obj:
        skew = int(policy.get("clock_skew_seconds", DEFAULT_CLOCK_SKEW_SECONDS))
        try:
            iat = int(obj["iat"])
        except (TypeError, ValueError):
            iat = None
        if iat is None or abs(iat - now_unix) > skew:
            reasons.append("timestamp_out_of_window")

    # Nonce gate: replay prevention against the store.
    nonce = obj.get("nonce") if isinstance(obj.get("nonce"), str) else obj.get("id")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_missing")
    elif nonce in store["items"]:
        reasons.append("nonce_replay")

    # Signed gate-vector claim: the proof commits to which gate it fails.
    marker = obj.get("marker")
    if marker != ALLOW_MARKER:
        reasons.append(MARKER_REASONS.get(marker, "unexpected_marker"))

    if reasons:
        deduped = list(dict.fromkeys(reasons))
        return {"decision": "deny", "reason_codes": deduped, "kind": "agegatex", "notes": notes}

    store["items"][nonce] = {"ts": now_unix}
    notes.append("nonce recorded in store")
    return {
        "decision": "allow",
        "reason_codes": [],
        "kind": "agegatex",
        "notes": notes,
    }
