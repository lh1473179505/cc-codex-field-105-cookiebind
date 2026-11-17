from __future__ import annotations
import base64
import binascii
import hashlib
import hmac
import os
import re
from typing import Any


SIGNING_VERSION = "v1"
SIGNED_FIELDS = (
    "kid",
    "symbol_server",
    "build_id",
    "file_name",
    "arch",
    "file_sha256",
    "path",
)


def _deny(reason: str, file_name: Any) -> dict:
    return {"decision": "deny", "reason_codes": [reason], "file_name": file_name}


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and value != ""


def _signing_message(obj: dict) -> str:
    parts = [SIGNING_VERSION]
    for field in SIGNED_FIELDS:
        parts.append(obj[field])
    parts.append(str(obj["iat"]))
    parts.append(obj["nonce"])
    return "|".join(parts)


def _decode_sig(sig: Any) -> bytes | None:
    if not isinstance(sig, str) or not sig:
        return None
    try:
        return base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
    except (binascii.Error, ValueError):
        return None


def _hmac_digest(secret_hex: str, message: str) -> bytes | None:
    try:
        key = bytes.fromhex(secret_hex)
    except (TypeError, ValueError):
        return None
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def inspect_symbol(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "symbol_server": obj.get("symbol_server"),
        "build_id": obj.get("build_id"),
        "file_name": obj.get("file_name"),
        "arch": obj.get("arch"),
        "file_sha256": obj.get("file_sha256"),
        "path": obj.get("path"),
        "nonce": obj.get("nonce"),
    }

def admit_symbol(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    if not isinstance(obj, dict):
        return _deny("malformed_symbol", None)

    file_name = obj.get("file_name")

    required = SIGNED_FIELDS + ("nonce", "iat", "sig")
    for field in required:
        if field not in obj:
            return _deny("missing_field", file_name)

    for field in SIGNED_FIELDS + ("nonce",):
        if not _is_text(obj[field]):
            return _deny("malformed_field", file_name)
    iat = obj["iat"]
    if isinstance(iat, bool) or not isinstance(iat, int):
        return _deny("malformed_iat", file_name)

    symbol_server = obj["symbol_server"]
    build_id = obj["build_id"]
    arch = obj["arch"]
    file_sha256 = obj["file_sha256"]
    path = obj["path"]
    kid = obj["kid"]
    nonce = obj["nonce"]

    server_pattern = policy.get("server_pattern", "")
    if not isinstance(server_pattern, str) or re.fullmatch(server_pattern, symbol_server) is None:
        return _deny("server_denied", file_name)
    server_entry = policy.get("servers", {}).get(symbol_server)
    if not isinstance(server_entry, dict):
        return _deny("server_denied", file_name)

    build_entry = server_entry.get("builds", {}).get(build_id)
    if not isinstance(build_entry, dict):
        return _deny("build_denied", file_name)

    for banned in policy.get("file_deny_substrings", []):
        if isinstance(banned, str) and banned in file_name:
            return _deny("file_denied", file_name)
    if file_name in (".", "..") or file_name != os.path.basename(file_name):
        return _deny("file_denied", file_name)
    file_entry = build_entry.get("files", {}).get(file_name)
    if not isinstance(file_entry, dict):
        return _deny("file_denied", file_name)

    if arch not in file_entry.get("arches", []):
        return _deny("arch_denied", file_name)

    hex_len = policy.get("sha256_hex_len", 64)
    if not isinstance(hex_len, int) or len(file_sha256) != hex_len:
        return _deny("digest_format", file_name)
    if re.fullmatch(r"[0-9a-f]{%d}" % hex_len, file_sha256) is None:
        return _deny("digest_format", file_name)
    if not hmac.compare_digest(file_sha256, str(file_entry.get("sha256", ""))):
        return _deny("digest_binding", file_name)

    for banned in policy.get("path_deny_substrings", []):
        if isinstance(banned, str) and banned in path:
            return _deny("path_denied", file_name)
    canonical_path = "/" + "/".join((build_id, arch, file_name))
    components = path[1:].split("/") if path.startswith("/") else []
    if len(components) != 3 or path != canonical_path:
        return _deny("path_denied", file_name)

    key_entry = keys.get("keys", {}).get(kid)
    if not isinstance(key_entry, dict):
        return _deny("unknown_kid", file_name)
    if key_entry.get("status") != "active":
        return _deny("key_revoked", file_name)

    provided_sig = _decode_sig(obj["sig"])
    expected_sig = _hmac_digest(str(key_entry.get("secret", "")), _signing_message(obj))
    if provided_sig is None or expected_sig is None or not hmac.compare_digest(provided_sig, expected_sig):
        return _deny("bad_sig", file_name)

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if now_unix < iat - skew or now_unix > iat + max_age + skew:
        return _deny("iat_expired", file_name)

    items = store.setdefault("items", {})
    if nonce in items:
        return _deny("nonce_replay", file_name)
    items[nonce] = {"ts": now_unix}

    return {"decision": "allow", "reason_codes": [], "file_name": file_name}
