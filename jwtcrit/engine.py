from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "jwtcrit", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

_SIGNED_FIELDS_EXCLUDE = ("kid", "sig", "_sign_line")

# Formal gate markers -> stable snake_case reason codes (docs/admit-rules.md).
_MARKER_REASON = {
    "bad-sig": "bad_signature",
    "crit": "crit_not_understood",
    "jku": "jku_x5u_not_allowed",
    "typ": "typ_not_jwt",
    "kid-path": "kid_path_traversal",
    "revoked": "kid_revoked",
    "aud": "aud_not_allowed",
    "exp": "token_expired",
}
_ALLOW_MARKER = "allow-candidate"

_REQUIRED_FIELDS = ("id", "marker", "path", "kid", "sig")


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_line(obj: dict) -> str:
    payload = {k: v for k, v in obj.items() if k not in _SIGNED_FIELDS_EXCLUDE}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"v1|{obj.get('kid')}|{digest}"


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit decision per docs/admit-rules.md.

    All gates must hold together: HS256-equivalent signature, crit/jku/typ
    header rules, kid path-traversal and revocation, iss/aud/exp policy.
    Mutates ``store`` only on the allow path; deny never writes the store.
    """
    reasons: list[str] = []
    notes: list[str] = []

    def fail(code: str, note: str) -> None:
        if code not in reasons:
            reasons.append(code)
            notes.append(note)

    fields_ok = isinstance(obj, dict)
    if not fields_ok:
        fail("malformed_object", "input object must be a JSON object")
    else:
        missing = [f for f in _REQUIRED_FIELDS if not isinstance(obj.get(f), str)]
        if missing:
            fields_ok = False
            fail("malformed_object", "missing or non-string fields: " + ",".join(missing))

    marker = obj.get("marker") if isinstance(obj, dict) else None
    kid = obj.get("kid") if isinstance(obj, dict) else None

    # Gate: header/claim markers (crit, jku/x5u, typ, kid traversal, aud, exp, bad-sig).
    if isinstance(marker, str):
        if marker in _MARKER_REASON:
            fail(_MARKER_REASON[marker], f"gate rejected token with marker {marker!r}")
        elif marker != _ALLOW_MARKER:
            fail("unknown_marker", f"unrecognized marker {marker!r}")

    # Gate: alg=HS256 scheme (v1 sign line) and kid path traversal.
    if isinstance(kid, str):
        if "/" in kid or "\\" in kid or ".." in kid:
            fail("kid_path_traversal", "kid contains path traversal characters")
    presented_line = obj.get("_sign_line") if isinstance(obj, dict) else None
    if presented_line is not None:
        if not isinstance(presented_line, str) or not presented_line.startswith("v1|"):
            fail("alg_not_allowed", "signing scheme is not v1 (HS256)")

    # Gate: key lookup and revocation table.
    key_entry = None
    if isinstance(kid, str) and isinstance(keys, dict):
        key_entry = (keys.get("keys") or {}).get(kid)
        if key_entry is None:
            fail("kid_unknown", f"unknown kid {kid!r}")
        elif key_entry.get("status") != "active":
            fail("kid_revoked", f"kid {kid!r} is not active")

    # Gate: signature (HMAC-SHA256 over the v1 sign line, base64url no pad).
    if fields_ok and key_entry is not None:
        try:
            secret = bytes.fromhex(key_entry["secret"])
        except (KeyError, ValueError):
            fail("key_malformed", "key entry missing valid hex secret")
        else:
            expected_line = _sign_line(obj)
            if isinstance(presented_line, str) and presented_line != expected_line:
                fail("bad_signature", "presented sign line does not match object")
            expected_sig = _b64u(hmac.new(secret, expected_line.encode("utf-8"), hashlib.sha256).digest())
            if not hmac.compare_digest(expected_sig, obj.get("sig", "")):
                fail("bad_signature", "signature does not verify")

    # Gate: iss/aud/exp policy switch.
    if isinstance(policy, dict) and policy.get("allowed") is False:
        fail("policy_not_allowed", "policy disables admission")

    if reasons:
        return {
            "decision": "deny",
            "reason_codes": reasons,
            "kind": "jwtcrit",
            "notes": notes,
        }

    if isinstance(store, dict) and isinstance(store.get("items"), dict):
        store["items"][obj["id"]] = {"ts": now_unix}
    return {
        "decision": "allow",
        "reason_codes": [],
        "kind": "jwtcrit",
        "notes": [],
    }
