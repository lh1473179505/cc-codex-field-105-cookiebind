from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_ptr(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "oid": obj.get("oid"),
        "size": obj.get("size"),
        "repo": obj.get("repo"),
        "path": obj.get("path"),
        "nonce": obj.get("nonce"),
    }

def admit_ptr(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []

    kid = obj.get("kid")
    oid = obj.get("oid")
    size = obj.get("size")
    repo = obj.get("repo")
    path = obj.get("path")
    nonce = obj.get("nonce")
    iat = obj.get("iat")
    sig = obj.get("sig")

    repos = policy.get("repos", {})
    repo_cfg = repos.get(repo)
    if repo_cfg is None:
        codes.append("repo_unknown")
    else:
        if not isinstance(path, str) or not any(
            path.startswith(p) for p in repo_cfg.get("path_prefixes", [])
        ):
            codes.append("path_prefix")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > repo_cfg.get("size_max", 0):
            codes.append("size_max")
        oid_prefix = repo_cfg.get("oid_prefix", "")
        hex_len = policy.get("oid_hex_len", 64)
        if (
            not isinstance(oid, str)
            or not oid.startswith(oid_prefix)
            or len(oid) != len(oid_prefix) + hex_len
            or any(c not in "0123456789abcdef" for c in oid[len(oid_prefix):])
        ):
            codes.append("oid_format")

    if not isinstance(path, str) or any(
        sub in path for sub in policy.get("path_deny_substrings", [])
    ):
        codes.append("path_deny")

    if not isinstance(iat, int) or isinstance(iat, bool):
        codes.append("iat_invalid")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            codes.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            codes.append("iat_expired")

    key_entry = keys.get("keys", {}).get(kid)
    if key_entry is None:
        codes.append("key_unknown")
    elif key_entry.get("status") != "active":
        codes.append("key_revoked")
    else:
        line = f"v1|{kid}|{oid}|{size}|{repo}|{path}|{iat}|{nonce}"
        secret = bytes.fromhex(key_entry.get("secret", ""))
        expect = base64.urlsafe_b64encode(
            hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
        if not isinstance(sig, str) or not hmac.compare_digest(expect, sig):
            codes.append("sig_invalid")

    items = store.setdefault("items", {})
    if nonce in items:
        codes.append("nonce_replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "oid": oid}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "oid": oid}
