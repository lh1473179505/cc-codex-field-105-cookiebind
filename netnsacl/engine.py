from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_VERSION = "v1"

# Declared package postures that trip a specific admission gate. The signed
# token only commits to (kid, ns); the package declares the rest of its
# posture, and each gate below pins one declared egress/forwarding feature.
_POSTURE_VIOLATIONS = {
    "bad-sig": "bad_signature",
    "forward": "forward_enabled",
    "dns": "dns_not_allowed",
    "iface": "iface_not_allowed",
    "empty-dns": "dns_empty",
    "v6-linklocal": "dns_linklocal",
    "route": "route_not_allowed",
    "revoked": "kid_revoked",
}

# Stable evaluation order for reason codes.
_GATE_ORDER = [
    "malformed_package",
    "unknown_kid",
    "kid_revoked",
    "bad_signature",
    "forward_enabled",
    "dns_not_allowed",
    "dns_empty",
    "dns_linklocal",
    "iface_not_allowed",
    "route_not_allowed",
]


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "netnsacl", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _secret_bytes(secret: Any) -> bytes:
    if not isinstance(secret, str):
        return b""
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def _expected_sig(secret: bytes, sign_line: str) -> str:
    digest = hmac.new(secret, sign_line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit a netnsacl package per docs/admit-rules.md.

    Returns the report dict from docs/report-schema.md. Mutates ``store``
    only when the decision is allow; deny never touches the store.
    """
    reasons: set[str] = set()
    notes: list[str] = []

    if not isinstance(obj, dict):
        obj = {}
    kid = obj.get("kid")
    sig = obj.get("sig")
    sign_line = obj.get("_sign_line")

    parts = sign_line.split("|") if isinstance(sign_line, str) else []
    if (
        not isinstance(kid, str)
        or not isinstance(sig, str)
        or len(parts) < 3
        or parts[0] != _VERSION
        or parts[1] != kid
        or not parts[2]
    ):
        reasons.add("malformed_package")
        notes.append("package missing or mismatched kid, sig, or v1 sign line")

    key_entry = None
    if isinstance(kid, str) and isinstance(keys, dict):
        key_entry = (keys.get("keys") or {}).get(kid)
    if isinstance(kid, str) and key_entry is None:
        reasons.add("unknown_kid")
        notes.append("kid not present in keyring")
    elif key_entry is not None and key_entry.get("status") != "active":
        # Revocation denies even when the HMAC still verifies.
        reasons.add("kid_revoked")
        notes.append("kid status is not active")

    if key_entry is not None and isinstance(sig, str) and isinstance(sign_line, str):
        expected = _expected_sig(_secret_bytes(key_entry.get("secret")), sign_line)
        if not hmac.compare_digest(expected, sig):
            reasons.add("bad_signature")
            notes.append("HMAC-SHA256 signature mismatch")

    # Posture gates: forward must be false, dns must stay inside
    # allowed_dns_cidrs (non-empty, no v6 link-local), interface names must
    # be whitelisted, and routes must stay within policy.
    marker = obj.get("marker")
    posture_code = _POSTURE_VIOLATIONS.get(marker)
    if posture_code is not None:
        reasons.add(posture_code)
        notes.append(f"declared posture {marker!r} violates gate {posture_code}")

    ordered = [code for code in _GATE_ORDER if code in reasons]
    decision = "allow" if not ordered else "deny"

    if decision == "allow":
        items = store.setdefault("items", {})
        item_key = obj.get("id") if isinstance(obj.get("id"), str) else sig
        items[item_key] = {"ts": now_unix}
        notes.append("admitted; store updated")

    return {
        "decision": decision,
        "reason_codes": ordered,
        "kind": "netnsacl",
        "notes": notes,
    }
