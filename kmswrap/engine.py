from __future__ import annotations
import base64
import hashlib
import hmac
import time
from datetime import datetime, timezone
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "kmswrap", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

_REQUIRED_FIELDS = ("id", "kid", "alg", "aad_b64", "aad_sha256", "wrapped_b64", "wrapped_sha256", "sig")


def _to_unix(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("epoch timestamps must be unix seconds or ISO-8601 strings")
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            pass
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    raise ValueError("epoch timestamps must be unix seconds or ISO-8601 strings")


def _b64decode(field: str, value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"field {field!r} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise ValueError(f"field {field!r} is not valid base64") from None


def _sign_line(kid: str, alg: str, aad_sha256: str, wrapped_sha256: str) -> str:
    return f"v1|{kid}|{alg}|{aad_sha256}|{wrapped_sha256}"


def _sign(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit a wrapped-DEK object per docs/admit-rules.md.

    Returns the report dict (docs/report-schema.md). On "allow" the admission
    is recorded into ``store`` (mutated in place); on "deny" the store is
    left untouched. Malformed inputs raise ValueError.
    """
    if not isinstance(obj, dict):
        raise ValueError("input object must be a JSON object")
    for field in _REQUIRED_FIELDS:
        if field not in obj:
            raise ValueError(f"input object missing field {field!r}")
    for field in ("id", "kid", "alg", "aad_sha256", "wrapped_sha256", "sig"):
        if not isinstance(obj[field], str):
            raise ValueError(f"field {field!r} must be a string")

    aad = _b64decode("aad_b64", obj["aad_b64"])
    wrapped = _b64decode("wrapped_b64", obj["wrapped_b64"])

    if not isinstance(policy, dict) or not isinstance(policy.get("allowed_wrap_algs"), list):
        raise ValueError("policy must define allowed_wrap_algs")
    allowed_algs = policy["allowed_wrap_algs"]
    min_wrapped = int(policy.get("min_wrapped_bytes", 0))
    skew = int(policy.get("clock_skew_seconds", 0))

    key_table = keys.get("keys", keys) if isinstance(keys, dict) else None
    if not isinstance(key_table, dict):
        raise ValueError("keys must be an object with a keys object")

    now = int(now_unix) if now_unix is not None else int(time.time())

    kid = obj["kid"]
    alg = obj["alg"]
    aad_sha256 = obj["aad_sha256"].lower()
    wrapped_sha256 = obj["wrapped_sha256"].lower()

    reasons: list[str] = []
    notes: list[str] = []

    def deny(code: str, note: str) -> None:
        reasons.append(code)
        notes.append(note)

    if alg not in allowed_algs:
        deny("alg_not_allowed", f"alg {alg!r} not in allowed_wrap_algs")
    if hashlib.sha256(aad).hexdigest() != aad_sha256:
        deny("aad_sha256_mismatch", "aad raw bytes do not hash to aad_sha256")
    if hashlib.sha256(wrapped).hexdigest() != wrapped_sha256:
        deny("wrapped_sha256_mismatch", "wrapped bytes do not hash to wrapped_sha256")
    if len(wrapped) < min_wrapped:
        deny("wrapped_too_short", f"wrapped length {len(wrapped)} below minimum {min_wrapped}")

    key = key_table.get(kid)
    if key is None:
        deny("unknown_kid", f"kek_kid {kid!r} not found in key store")
    else:
        if key.get("status") == "revoked":
            deny("key_revoked", f"kek_kid {kid!r} is revoked")
        not_before = _to_unix(key.get("not_before", 0))
        not_after = _to_unix(key.get("not_after", 0))
        if now < not_before - skew or now > not_after + skew:
            deny("key_outside_epoch", f"kek_kid {kid!r} outside its validity epoch at now={now}")
        expected = _sign(key["secret"], _sign_line(kid, alg, obj["aad_sha256"], obj["wrapped_sha256"]))
        if not hmac.compare_digest(expected, obj["sig"]):
            deny("bad_signature", "HMAC-SHA256 signature verification failed")

    decision = "deny" if reasons else "allow"
    if decision == "allow":
        items = store.setdefault("items", {})
        items[obj["id"]] = {"ts": now}
    return {
        "decision": decision,
        "reason_codes": reasons,
        "kind": "kmswrap",
        "notes": notes,
    }
