from __future__ import annotations
import base64
import hashlib
import hmac
import re
import time
from typing import Any

SIGN_VERSION = "v1"
DIGEST_PREFIX = "sha256:"
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "cosignoff", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _sign_line(kid: str, digest: str, identity: str, issuer: str, iat: int) -> str:
    return f"{SIGN_VERSION}|{kid}|{digest}|{identity}|{issuer}|{iat}"


def _b64url_hmac_sha256(secret: bytes, line: str) -> str:
    mac = hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def _require_str(obj: dict, field: str) -> str:
    value = obj.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"input field {field!r} must be a non-empty string")
    return value


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit or deny a signed image attestation per docs/admit-rules.md.

    On allow, records the signature in ``store["items"]`` (mutated in place)
    so callers can persist it; on deny the store is left untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(keys, dict) or not isinstance(keys.get("keys"), dict):
        raise ValueError("keys must be an object with a 'keys' object")
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be an object with an 'items' object")

    kid = _require_str(obj, "kid")
    digest = _require_str(obj, "digest")
    identity = _require_str(obj, "identity")
    issuer = _require_str(obj, "issuer")
    image = _require_str(obj, "image")
    sig = _require_str(obj, "sig")
    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        raise ValueError("input field 'iat' must be an integer unix timestamp")

    policy_issuer = policy.get("issuer")
    identity_pattern = policy.get("allow_identity_regex")
    skew = policy.get("clock_skew_seconds")
    max_age = policy.get("max_age_seconds")
    if not isinstance(policy_issuer, str) or not policy_issuer:
        raise ValueError("policy.issuer must be a non-empty string")
    if not isinstance(identity_pattern, str) or not identity_pattern:
        raise ValueError("policy.allow_identity_regex must be a non-empty string")
    if not isinstance(skew, int) or isinstance(skew, bool) or skew < 0:
        raise ValueError("policy.clock_skew_seconds must be a non-negative integer")
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 0:
        raise ValueError("policy.max_age_seconds must be a non-negative integer")
    try:
        identity_re = re.compile(identity_pattern)
    except re.error as exc:
        raise ValueError(f"policy.allow_identity_regex is not a valid regex: {exc}")

    if now_unix is None:
        now_unix = int(time.time())

    reasons: list[str] = []

    if policy.get("allowed", True) is False:
        reasons.append("policy_disabled")

    key_entry = keys["keys"].get(kid)
    if key_entry is None:
        reasons.append("kid_unknown")
    else:
        secret_hex = key_entry.get("secret")
        if not isinstance(secret_hex, str):
            raise ValueError(f"keys.keys[{kid!r}].secret must be a hex string")
        try:
            secret = bytes.fromhex(secret_hex)
        except ValueError:
            raise ValueError(f"keys.keys[{kid!r}].secret must be a hex string")
        line = _sign_line(kid, digest, identity, issuer, iat)
        expected = _b64url_hmac_sha256(secret, line)
        if not hmac.compare_digest(expected, sig):
            reasons.append("signature_invalid")
        if key_entry.get("status") != "active":
            reasons.append("kid_revoked")

    if not DIGEST_RE.fullmatch(digest):
        reasons.append("digest_algorithm")
    elif digest != image:
        reasons.append("digest_mismatch")

    if not identity_re.search(identity):
        reasons.append("identity_not_allowed")

    if issuer != policy_issuer:
        reasons.append("issuer_mismatch")

    if iat > now_unix + skew or iat < now_unix - max_age:
        reasons.append("iat_out_of_window")

    if sig in store["items"]:
        reasons.append("replay")

    decision = "deny" if reasons else "allow"
    if decision == "allow":
        store["items"][sig] = {"ts": iat}

    return {
        "decision": decision,
        "reason_codes": reasons,
        "kind": policy.get("pkg", "cosignoff"),
        "notes": [],
    }
