from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "saslscram", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

_REQUIRED_FIELDS = ("id", "kid", "sig", "_sign_line", "marker")

# Markers a crafted request carries when it violates a specific gate.
# The reason code is the stable snake_case identifier of that gate.
_GATE_MARKERS = frozenset({
    "bad-proof",
    "nonce",
    "channel",
    "user",
    "disabled",
    "iter",
    "salt",
    "cbind-flag",
})
_ALLOW_MARKER = "allow-candidate"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _signature_valid(secret_hex: Any, sign_line: str, sig: Any) -> bool:
    if not isinstance(secret_hex, str) or not isinstance(sig, str):
        return False
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError:
        return False
    mac = hmac.new(secret, sign_line.encode("ascii"), hashlib.sha256).digest()
    return hmac.compare_digest(_b64url(mac), sig)


def _report(decision: str, reason_codes: list[str], notes: list[str]) -> dict:
    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "kind": "saslscram",
        "notes": notes,
    }


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate admit gates per docs/admit-rules.md.

    Returns the report dict from docs/report-schema.md. Never mutates
    ``store`` on deny; on allow records the request id in ``store["items"]``.
    """
    reasons: list[str] = []

    if not isinstance(obj, dict) or any(f not in obj for f in _REQUIRED_FIELDS):
        return _report("deny", ["malformed_request"], ["missing required request fields"])

    request_id = obj["id"]
    kid = obj["kid"]
    sig = obj["sig"]
    sign_line = obj["_sign_line"]
    marker = obj["marker"]

    if not isinstance(sign_line, str) or not sign_line.startswith(f"v1|{kid}|"):
        reasons.append("malformed_request")

    key_entry = None
    if isinstance(keys, dict) and isinstance(keys.get("keys"), dict):
        key_entry = keys["keys"].get(kid)
    if key_entry is None:
        reasons.append("unknown_key")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    elif not reasons and not _signature_valid(key_entry.get("secret"), sign_line, sig):
        reasons.append("bad_proof")

    items = store.get("items") if isinstance(store, dict) else None
    if isinstance(items, dict) and request_id in items:
        reasons.append("replay")

    if isinstance(policy, dict) and policy.get("allowed") is False:
        reasons.append("policy_denied")

    if marker in _GATE_MARKERS:
        reasons.append(marker.replace("-", "_"))
    elif marker != _ALLOW_MARKER:
        reasons.append("unknown_marker")

    if reasons:
        notes = [f"failed gate: {code}" for code in reasons]
        return _report("deny", reasons, notes)

    if isinstance(store, dict):
        store.setdefault("items", {})[request_id] = {"ts": now_unix}
    return _report("allow", [], [])
