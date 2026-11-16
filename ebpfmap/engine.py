from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_REQUIRED_FIELDS = (
    "kid",
    "map_id",
    "key_hex",
    "value_sha256",
    "pin",
    "nonce",
    "iat",
    "sig",
)


def _is_hex(s: Any) -> bool:
    return isinstance(s, str) and len(s) > 0 and all(ch in _HEX_DIGITS for ch in s)


def _b64url_decode(s: Any) -> bytes | None:
    if not isinstance(s, str) or not s:
        return None
    pad = "=" * (-len(s) % 4)
    try:
        return base64.urlsafe_b64decode(s + pad)
    except (ValueError, TypeError):
        return None


def _deny(map_id: Any, reason: str) -> dict:
    return {"decision": "deny", "reason_codes": [reason], "map_id": map_id}

def inspect_upd(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "map_id": obj.get("map_id"),
        "key_hex": obj.get("key_hex"),
        "value_sha256": obj.get("value_sha256"),
        "pin": obj.get("pin"),
        "nonce": obj.get("nonce"),
    }

def admit_upd(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    map_id = obj.get("map_id")

    if not isinstance(obj, dict) or any(field not in obj for field in _REQUIRED_FIELDS):
        return _deny(map_id, "malformed")

    maps = policy.get("maps", {})
    map_conf = maps.get(map_id) if isinstance(maps, dict) else None
    if not isinstance(map_conf, dict):
        return _deny(map_id, "unknown_map")

    key_hex = obj["key_hex"]
    key_bytes = map_conf.get("key_bytes")
    if not isinstance(key_bytes, int) or not _is_hex(key_hex) or len(key_hex) != key_bytes * 2:
        return _deny(map_id, "bad_key_len")

    value_sha256 = obj["value_sha256"]
    want_len = policy.get("value_sha256_hex_len", 64)
    if not _is_hex(value_sha256) or len(value_sha256) != want_len:
        return _deny(map_id, "bad_value_digest")

    pin = obj["pin"]
    pin_prefix = map_conf.get("pin_prefix", "")
    if not isinstance(pin, str) or not pin.startswith(pin_prefix):
        return _deny(map_id, "bad_pin_prefix")
    for deny_part in policy.get("pin_deny_substrings", []):
        if isinstance(deny_part, str) and deny_part and deny_part in pin:
            return _deny(map_id, "pin_deny_substring")

    key_entry = keys.get("keys", {}).get(obj["kid"]) if isinstance(keys, dict) else None
    if not isinstance(key_entry, dict):
        return _deny(map_id, "unknown_kid")
    if key_entry.get("status") != "active":
        return _deny(map_id, "key_revoked")

    try:
        secret = bytes.fromhex(key_entry["secret"])
    except (KeyError, TypeError, ValueError):
        return _deny(map_id, "bad_key_secret")

    signing_input = "|".join((
        "v1",
        str(obj["kid"]),
        str(map_id),
        key_hex,
        value_sha256,
        pin,
        str(obj["iat"]),
        str(obj["nonce"]),
    ))
    expected = hmac.new(secret, signing_input.encode("utf-8"), hashlib.sha256).digest()
    provided = _b64url_decode(obj["sig"])
    if provided is None or not hmac.compare_digest(expected, provided):
        return _deny(map_id, "bad_sig")

    iat = obj["iat"]
    if not isinstance(iat, int) or isinstance(iat, bool):
        return _deny(map_id, "bad_iat")
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if iat > now_unix + skew:
        return _deny(map_id, "iat_future")
    if iat < now_unix - max_age - skew:
        return _deny(map_id, "iat_expired")

    items = store.setdefault("items", {})
    nonce = obj["nonce"]
    if not isinstance(nonce, str) or not nonce or nonce in items:
        return _deny(map_id, "nonce_replay")

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "map_id": map_id}
