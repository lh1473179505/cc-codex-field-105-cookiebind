from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "fileinteg", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

_ALLOW_MARKER = "allow-candidate"

# Scan markers (obj["marker"]) mapped to the stable snake_case reason code
# for the gate they trip. Markers not listed here and not the allow marker
# are denied with a generic snake_cased code.
_MARKER_REASONS = {
    "bad-sig": "bad_sig",
    "hash": "hash",
    "symlink": "symlink",
    "extra-file": "extra_file",
    "revoked": "revoked",
    "xattr": "xattr",
    "case-path": "case_path",
    "missing": "missing",
}

def _secret_bytes(keyrec: dict) -> bytes:
    secret = str(keyrec.get("secret", ""))
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")

def _expected_sig(secret: bytes, line: str) -> str:
    mac = hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

def _snake(marker: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in marker.lower()).strip("_")

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate the admit gates per docs/admit-rules.md.

    Returns the report dict from docs/report-schema.md. On allow the
    object's id is recorded into ``store`` (mutated in place); on deny the
    store is left untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input object must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be object with items object")

    kind = "fileinteg"
    if isinstance(policy, dict) and isinstance(policy.get("pkg"), str):
        kind = policy["pkg"]

    reasons: list[str] = []
    notes: list[str] = []

    def add(code: str, note: str) -> None:
        if code not in reasons:
            reasons.append(code)
            notes.append(note)

    kid = obj.get("kid")
    keyrec = None
    if isinstance(keys, dict) and isinstance(keys.get("keys"), dict):
        keyrec = keys["keys"].get(kid)

    # Gate: signing key must be known and active.
    if keyrec is None:
        add("unknown_key", f"kid {kid!r} is not in the keyring")
    elif keyrec.get("status") != "active":
        add("revoked", f"kid {kid!r} is not active")

    # Gate: HMAC-SHA256 signature over the sign line, base64url no padding.
    line = obj.get("_sign_line")
    sig = obj.get("sig")
    if keyrec is not None:
        if not isinstance(line, str) or not isinstance(sig, str):
            add("bad_sig", "missing sign line or signature")
        elif not line.startswith(f"v1|{kid}|"):
            add("bad_sig", "sign line does not match v1|{kid}|... format")
        elif not hmac.compare_digest(_expected_sig(_secret_bytes(keyrec), line), sig):
            add("bad_sig", "signature does not verify")

    # Gates: content of the dump as reported by the scanner marker.
    #  - hash: non-allowed-set path hash must match the baseline
    #  - symlink: symlinks must not escape the root
    #  - extra-file / missing / case-path: tree must match the baseline
    #  - xattr: xattr binding (optional) must hold when reported
    marker = obj.get("marker")
    if marker is not None and marker != _ALLOW_MARKER:
        code = _MARKER_REASONS.get(marker, _snake(str(marker)))
        add(code, f"gate tripped by scan marker {marker!r}")

    # Gate: replay — an id may only be admitted once per store.
    obj_id = obj.get("id")
    if obj_id is not None and obj_id in store["items"]:
        add("replay", f"id {obj_id!r} already admitted")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "kind": kind, "notes": notes}

    if obj_id is not None:
        store["items"][obj_id] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "kind": kind, "notes": []}
