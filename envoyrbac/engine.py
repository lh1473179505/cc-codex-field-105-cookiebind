from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_req(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "principal": obj.get("principal"),
        "path": obj.get("path"),
        "method": obj.get("method"),
        "headers": obj.get("headers"),
        "nonce": obj.get("nonce"),
    }

def _headers_csv(headers: dict) -> str:
    return ",".join(f"{k}={headers[k]}" for k in sorted(headers))

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{principal}|{path}|{method}|{headers_csv}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        principal=obj.get("principal"),
        path=obj.get("path"),
        method=obj.get("method"),
        headers_csv=_headers_csv(obj.get("headers") or {}),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _path_allowed(path: str, prefixes: list) -> bool:
    for prefix in prefixes:
        if prefix.endswith("/"):
            if path.startswith(prefix):
                return True
        elif path == prefix:
            return True
    return False

def admit_req(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    path = obj.get("path") or ""
    reasons: list[str] = []

    for sub in policy.get("path_deny_substrings", []):
        if sub in path:
            reasons.append("path_deny")
            break
    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "path": obj.get("path")}

    principal = obj.get("principal")
    entry = (policy.get("principals") or {}).get(principal)
    if entry is None:
        reasons.append("principal_unknown")
    else:
        if not _path_allowed(path, entry.get("path_prefixes") or []):
            reasons.append("path_prefix")
        if obj.get("method") not in (entry.get("methods") or []):
            reasons.append("method_not_allowed")
        headers = obj.get("headers") or {}
        for name, want in (entry.get("require_headers") or {}).items():
            if name not in headers:
                reasons.append("header_missing")
            elif want is not None and headers[name] != want:
                reasons.append("header_value_mismatch")
        for name in entry.get("deny_headers") or []:
            if name in headers:
                reasons.append("header_denied")

    key = (keys.get("keys") or {}).get(obj.get("kid"))
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        try:
            secret = bytes.fromhex(key.get("secret") or "")
        except ValueError:
            secret = b""
        digest = hmac.new(secret, _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
        expect = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expect, str(obj.get("sig"))):
            reasons.append("sig_invalid")

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + skew:
            reasons.append("iat_future")
        if now_unix - iat > max_age:
            reasons.append("iat_stale")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "path": obj.get("path")}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "path": obj.get("path")}
