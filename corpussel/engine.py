from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_seed(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "target": obj.get("target"),
        "input_sha256": obj.get("input_sha256"),
        "size": obj.get("size"),
        "coverage_edges": obj.get("coverage_edges"),
        "format": obj.get("format"),
        "timeout_ms": obj.get("timeout_ms"),
        "nonce": obj.get("nonce"),
    }

def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)

def _deny(target: Any, code: str) -> dict:
    return {"decision": "deny", "reason_codes": [code], "target": target}

def _signing_line(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj["kid"]),
        str(obj["target"]),
        str(obj["input_sha256"]),
        str(obj["size"]),
        str(obj["coverage_edges"]),
        str(obj["format"]),
        str(obj["timeout_ms"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ])

def admit_seed(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    target = obj.get("target")

    targets = policy.get("targets", {})
    if not isinstance(target, str) or target not in targets:
        return _deny(target, "target")
    target_cfg = targets[target]

    fmt = obj.get("format")
    formats = target_cfg.get("formats", {})
    if not isinstance(fmt, str) or fmt not in formats:
        return _deny(target, "format")
    fmt_cfg = formats[fmt]

    digest = obj.get("input_sha256")
    hex_len = policy.get("sha256_hex_len", 64)
    if not isinstance(digest, str) or len(digest) != hex_len:
        return _deny(target, "digest_length")
    if re.fullmatch(r"[0-9a-f]*", digest) is None:
        return _deny(target, "digest_case")

    size = obj.get("size")
    if not _is_int(size):
        return _deny(target, "size_min")
    if size < fmt_cfg["size_min"]:
        return _deny(target, "size_min")
    if size > fmt_cfg["size_max"]:
        return _deny(target, "size_max")

    coverage = obj.get("coverage_edges")
    if not _is_int(coverage):
        return _deny(target, "coverage_min")
    if coverage < fmt_cfg["coverage_min"]:
        return _deny(target, "coverage_min")
    if coverage > fmt_cfg["coverage_max"]:
        return _deny(target, "coverage_max")
    if coverage > size * target_cfg["max_edges_per_byte"]:
        return _deny(target, "coverage_density")

    timeout_ms = obj.get("timeout_ms")
    if not _is_int(timeout_ms) or timeout_ms not in fmt_cfg["timeouts_ms"]:
        return _deny(target, "timeout")

    kid = obj.get("kid")
    key_entries = keys.get("keys", {})
    if not isinstance(kid, str) or kid not in key_entries:
        return _deny(target, "unknown_kid")
    key_cfg = key_entries[kid]
    if key_cfg.get("status") != "active":
        return _deny(target, "revoked")

    try:
        secret = bytes.fromhex(key_cfg["secret"])
    except (TypeError, ValueError):
        return _deny(target, "bad_sig")
    mac = hmac.new(
        secret, _signing_line(obj).encode("utf-8"), hashlib.sha256
    ).digest()
    expected_sig = base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")
    sig = obj.get("sig")
    if not isinstance(sig, str) or not hmac.compare_digest(sig, expected_sig):
        return _deny(target, "bad_sig")

    iat = obj.get("iat")
    if not _is_int(iat):
        return _deny(target, "iat_window")
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if iat < now_unix - max_age or iat > now_unix + skew:
        return _deny(target, "iat_window")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return _deny(target, "bad_nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        return _deny(target, "replay")

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "target": target}
