from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_capability(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "module": obj.get("module"),
        "path": obj.get("path"),
        "preopen": obj.get("preopen"),
        "read": obj.get("read"),
        "write": obj.get("write"),
        "nonce": obj.get("nonce"),
    }

def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)

def _signing_input(kid, module, path, preopen, read, write, iat, nonce) -> str:
    return f"v1|{kid}|{module}|{path}|{preopen}|{read}|{write}|{iat}|{nonce}"

def _check_path(path: Any, entry: dict, policy: dict) -> list[str]:
    codes: list[str] = []
    if not isinstance(path, str) or not path:
        return ["path_invalid"]
    if path.startswith("/"):
        codes.append("path_absolute")
    for sub in policy.get("path_deny_substrings", []):
        if sub and sub in path:
            codes.append("path_traversal")
            break
    parts = path.split("/")
    if any(p in ("", ".", "..") for p in parts):
        if "path_traversal" not in codes:
            codes.append("path_traversal")
    if not any(path.startswith(prefix) for prefix in entry.get("path_prefixes", [])):
        codes.append("path_prefix")
    return codes

def admit_capability(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    module = obj.get("module") if isinstance(obj, dict) else None

    def deny(codes: list[str]) -> dict:
        return {"decision": "deny", "reason_codes": codes, "module": module}

    if not isinstance(obj, dict):
        return deny(["capability_shape"])
    kid = obj.get("kid")
    path = obj.get("path")
    preopen = obj.get("preopen")
    read = obj.get("read")
    write = obj.get("write")
    iat = obj.get("iat")
    nonce = obj.get("nonce")
    sig = obj.get("sig")
    if not all(isinstance(v, str) for v in (kid, module, path, preopen, nonce, sig)):
        return deny(["capability_shape"])
    if not _is_int(read) or not _is_int(write) or not _is_int(iat):
        return deny(["capability_shape"])

    key = keys.get("keys", {}).get(kid)
    if key is None:
        return deny(["unknown_key"])
    if key.get("status") != "active":
        return deny(["key_revoked"])

    msg = _signing_input(kid, module, path, preopen, read, write, iat, nonce)
    expected = hmac.new(bytes.fromhex(key["secret"]), msg.encode("utf-8"), hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(expected_b64, sig):
        return deny(["bad_signature"])

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if iat > now_unix + skew:
        return deny(["iat_future"])
    if now_unix - iat > max_age:
        return deny(["iat_stale"])

    items = store.get("items", {})
    if nonce in items:
        return deny(["nonce_replay"])

    entry = policy.get("modules", {}).get(module)
    if entry is None:
        return deny(["unknown_module"])
    if preopen != entry.get("preopen"):
        return deny(["preopen_mismatch"])

    path_codes = _check_path(path, entry, policy)
    if path_codes:
        return deny(path_codes)

    perm_codes: list[str] = []
    allowed_values = policy.get("permission_values", [0, 1])
    if read not in allowed_values or write not in allowed_values:
        perm_codes.append("permission_value")
    elif read == 0 and write == 0:
        perm_codes.append("permission_empty")
    else:
        if read == 1 and not entry.get("read_allowed", False):
            perm_codes.append("read_not_allowed")
        if write == 1:
            if not entry.get("write_allowed", False):
                perm_codes.append("write_not_allowed")
            elif not any(path.startswith(p) for p in entry.get("write_prefixes", [])):
                perm_codes.append("write_prefix")
    if perm_codes:
        return deny(perm_codes)

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "module": module}
