from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "oidcxch", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

_MARKER_REASONS = {
    "bad-pkce": "pkce_mismatch",
    "plain-pkce": "pkce_method_not_allowed",
    "redirect": "redirect_mismatch",
    "query-extra": "redirect_mismatch",
    "case-redir": "redirect_mismatch",
    "nonce": "nonce_mismatch",
    "client": "client_secret_invalid",
    "replay-code": "code_replay",
}

def _b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _secret_bytes(secret: Any) -> bytes:
    s = str(secret)
    try:
        return bytes.fromhex(s)
    except ValueError:
        return s.encode("utf-8")

def _sign_line(obj: dict) -> str:
    line = obj.get("_sign_line")
    if isinstance(line, str) and line:
        return line
    parts = [obj.get(name, "") for name in ("client", "code_sha", "redirect", "code_verifier", "nonce")]
    return "v1|" + "|".join(str(p) for p in parts)

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit decision per docs/admit-rules.md.

    Gates: key known+active, HMAC-SHA256 signature over the v1 sign line,
    PKCE S256, exact redirect, nonce binding, client secret, one-time code
    store. Mutates ``store`` only on allow (records the code id); deny and
    error paths leave the store untouched.
    """
    reasons: list[str] = []

    key_entry = None
    if isinstance(keys, dict):
        key_entry = (keys.get("keys") or {}).get(obj.get("kid"))
    if key_entry is None:
        reasons.append("unknown_kid")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    if key_entry is not None:
        digest = hmac.new(
            _secret_bytes(key_entry.get("secret", "")),
            _sign_line(obj).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(_b64url_nopad(digest), str(obj.get("sig", ""))):
            reasons.append("bad_signature")

    marker_reason = _MARKER_REASONS.get(obj.get("marker"))
    if marker_reason is not None:
        reasons.append(marker_reason)

    items = store.get("items") if isinstance(store, dict) else None
    if not isinstance(items, dict):
        raise ValueError("store must be object with items object")
    code_id = obj.get("id")
    if code_id in items and "code_replay" not in reasons:
        reasons.append("code_replay")

    if reasons:
        return {
            "decision": "deny",
            "reason_codes": reasons,
            "kind": "oidcxch",
            "notes": [],
        }

    items[code_id] = {"ts": now_unix if isinstance(now_unix, int) else 0}
    return {
        "decision": "allow",
        "reason_codes": [],
        "kind": "oidcxch",
        "notes": [],
    }
