from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_upload(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "root": obj.get("root"),
        "path": obj.get("path"),
        "size": obj.get("size"),
        "mode": obj.get("mode"),
        "sha256": obj.get("sha256"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{user}|{root}|{path}|{size}|{mode}|{sha256}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        user=obj.get("user"),
        root=obj.get("root"),
        path=obj.get("path"),
        size=obj.get("size"),
        mode=obj.get("mode"),
        sha256=obj.get("sha256"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_upload(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []

    users = policy.get("users", {})
    user = obj.get("user")
    entry = users.get(user) if isinstance(user, str) else None
    if entry is None:
        reasons.append("unknown_user")
        entry = {}

    root = obj.get("root")
    if entry.get("root") is not None and root != entry.get("root"):
        reasons.append("root_mismatch")

    path = obj.get("path")
    if not isinstance(path, str) or not path:
        reasons.append("path_invalid")
    else:
        if policy.get("forbid_absolute_path") and path.startswith("/"):
            reasons.append("absolute_path")
        for sub in policy.get("path_deny_substrings", []):
            if sub and sub in path:
                reasons.append("unsafe_path")
                break
        parts = path.split("/")
        if any(p in ("", ".", "..") for p in parts):
            reasons.append("bad_path_component")
        prefixes = entry.get("path_prefixes", [])
        if prefixes and not any(path.startswith(p) for p in prefixes):
            reasons.append("path_prefix")

    size = obj.get("size")
    size_min = policy.get("size_min", 1)
    size_max = entry.get("size_max")
    if isinstance(size, bool) or not isinstance(size, int):
        reasons.append("size_invalid")
    elif size < size_min or (size_max is not None and size > size_max):
        reasons.append("size_range")

    mode = obj.get("mode")
    modes = entry.get("modes", [])
    if not isinstance(mode, str) or mode not in modes:
        reasons.append("mode_not_allowed")

    digest = obj.get("sha256")
    hex_len = policy.get("sha256_hex_len", 64)
    if not isinstance(digest, str) or len(digest) != hex_len:
        reasons.append("sha256_format")
    else:
        alphabet = "0123456789abcdef" if policy.get("require_lowercase_hex") else "0123456789abcdefABCDEF"
        if any(c not in alphabet for c in digest):
            reasons.append("sha256_format")

    iat = obj.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat > now_unix + skew:
            reasons.append("iat_future")
        if now_unix - iat > max_age:
            reasons.append("iat_expired")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if key_entry is None:
        reasons.append("unknown_kid")
    else:
        if key_entry.get("status") != "active":
            reasons.append("key_not_active")
        sig = obj.get("sig")
        if not isinstance(sig, str) or not hmac.compare_digest(
            sig, _expected_sig(key_entry.get("secret", ""), _signing_line(obj))
        ):
            reasons.append("bad_signature")

    nonce = obj.get("nonce")
    items = store.get("items", {})
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "path": obj.get("path")}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "path": obj.get("path")}
