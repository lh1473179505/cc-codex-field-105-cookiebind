from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any


_HEX_DIGITS = "0123456789abcdef"
_REQUIRED_FIELDS = (
    "kid",
    "engine_id",
    "user",
    "auth",
    "priv",
    "oid",
    "varbinds",
    "severity",
    "iat",
    "nonce",
    "sig",
)


def inspect_trap(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "engine_id": obj.get("engine_id"),
        "user": obj.get("user"),
        "auth": obj.get("auth"),
        "priv": obj.get("priv"),
        "oid": obj.get("oid"),
        "varbinds": obj.get("varbinds"),
        "severity": obj.get("severity"),
        "nonce": obj.get("nonce"),
    }


def _is_lowercase_hex(value: str) -> bool:
    return len(value) > 0 and all(ch in _HEX_DIGITS for ch in value)


def _oid_parts(value: Any) -> list[str] | None:
    if not isinstance(value, str) or not value:
        return None
    parts = value.split(".")
    validated: list[str] = []
    for part in parts:
        if not part or not part.isascii() or not part.isdigit():
            return None
        if len(part) > 1 and part[0] == "0":
            return None
        validated.append(part)
    if len(validated) < 2:
        return None
    return validated


def _prefix_parts(prefix: Any) -> list[str] | None:
    if not isinstance(prefix, str) or not prefix:
        return None
    text = prefix[:-1] if prefix.endswith(".") else prefix
    parts = text.split(".")
    validated: list[str] = []
    for part in parts:
        if not part or not part.isascii() or not part.isdigit():
            return None
        if len(part) > 1 and part[0] == "0":
            return None
        validated.append(part)
    if not validated:
        return None
    return validated


def _oid_under(oid_parts: list[str], prefix: Any) -> bool:
    prefix_parts = _prefix_parts(prefix)
    if prefix_parts is None or len(oid_parts) < len(prefix_parts):
        return False
    return oid_parts[: len(prefix_parts)] == prefix_parts


def admit_trap(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    oid = obj.get("oid")

    missing = any(
        obj.get(name) is None or obj.get(name) == ""
        for name in _REQUIRED_FIELDS
        if name != "varbinds"
    ) or obj.get("varbinds") is None
    if missing:
        reasons.append("missing_field")

    keyring = keys.get("keys", {}) if isinstance(keys, dict) else {}
    kid = obj.get("kid")
    key_entry = keyring.get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        reasons.append("unknown_key")
    elif key_entry.get("status") != "active":
        reasons.append("revoked_key")

    if key_entry is not None and not missing:
        varbinds = obj.get("varbinds")
        if not isinstance(varbinds, list) or not all(
            isinstance(item, str) for item in varbinds
        ):
            reasons.append("bad_signature")
        else:
            try:
                key_material = bytes.fromhex(key_entry["secret"])
                line_fields = {
                    name: obj.get(name)
                    for name in (
                        "kid",
                        "engine_id",
                        "user",
                        "auth",
                        "priv",
                        "oid",
                        "severity",
                        "iat",
                        "nonce",
                    )
                }
                line_fields["varbinds"] = ",".join(varbinds)
                line = (
                    "v1|{kid}|{engine_id}|{user}|{auth}|{priv}|{oid}|"
                    "{varbinds}|{severity}|{iat}|{nonce}"
                ).format(**line_fields)
                digest = hmac.new(
                    key_material, line.encode("utf-8"), hashlib.sha256
                ).digest()
                expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
                given = obj.get("sig")
                if not isinstance(given, str) or not hmac.compare_digest(
                    expected, given.rstrip("=")
                ):
                    reasons.append("bad_signature")
            except (ValueError, TypeError, KeyError):
                reasons.append("bad_signature")

    engines = policy.get("engines", {}) if isinstance(policy, dict) else {}
    if not isinstance(engines, dict):
        engines = {}
    hex_len = policy.get("engine_id_hex_len")
    engine_id = obj.get("engine_id")
    engine = None
    engine_ok = (
        isinstance(engine_id, str)
        and isinstance(hex_len, int)
        and len(engine_id) == hex_len
    )
    if engine_ok:
        if policy.get("require_lowercase_hex", True):
            engine_ok = _is_lowercase_hex(engine_id)
        else:
            engine_ok = all(
                ch in "0123456789abcdefABCDEF" for ch in engine_id
            )
    if not engine_ok:
        reasons.append("bad_engine_id")
    engine = engines.get(engine_id) if isinstance(engine_id, str) else None
    if engine is None and engine_ok:
        for configured_id, configured_engine in engines.items():
            if (
                isinstance(configured_id, str)
                and _is_lowercase_hex(configured_id)
                and (
                    configured_id.startswith(engine_id)
                    or engine_id.startswith(configured_id)
                )
            ):
                engine = configured_engine
                break
    if engine is None:
        reasons.append("bad_engine_id")

    user_cfg = None
    if engine is not None:
        users = engine.get("users", {})
        user = obj.get("user")
        user_cfg = users.get(user) if isinstance(user, str) else None
        if user_cfg is None:
            reasons.append("unknown_user")

    if user_cfg is not None:
        if obj.get("auth") not in user_cfg.get("auth", []):
            reasons.append("bad_auth")
        priv = obj.get("priv")
        if policy.get("require_authPriv", False) and priv in (None, "none"):
            reasons.append("bad_privacy")
        elif priv not in user_cfg.get("priv", []):
            reasons.append("bad_privacy")
        if obj.get("severity") not in user_cfg.get("severities", []):
            reasons.append("bad_severity")

    trap_parts = _oid_parts(obj.get("oid"))
    matched_prefixes: list[str] = []
    if user_cfg is not None:
        if trap_parts is None:
            reasons.append("bad_oid")
        else:
            for prefix in user_cfg.get("oid_prefixes", []):
                if _oid_under(trap_parts, prefix):
                    matched_prefixes.append(prefix)
            if not matched_prefixes:
                reasons.append("bad_oid")

    varbinds = obj.get("varbinds")
    if not isinstance(varbinds, list):
        reasons.append("bad_varbind_count")
    else:
        count_min = policy.get("varbind_count_min")
        count_max = policy.get("varbind_count_max")
        if not (
            isinstance(count_min, int)
            and isinstance(count_max, int)
            and count_min <= len(varbinds) <= count_max
        ):
            reasons.append("bad_varbind_count")
        global_prefix = policy.get("varbind_prefix")
        for varbind in varbinds:
            varbind_parts = _oid_parts(varbind)
            valid = (
                varbind_parts is not None
                and _oid_under(varbind_parts, global_prefix)
                and any(
                    _oid_under(varbind_parts, prefix)
                    for prefix in matched_prefixes
                )
            )
            if not valid:
                reasons.append("bad_varbind")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_window")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if not (now_unix - max_age <= iat <= now_unix + skew):
            reasons.append("iat_window")

    nonce = obj.get("nonce")
    if isinstance(nonce, str) and nonce:
        items = store.get("items", {}) if isinstance(store, dict) else {}
        if nonce in items:
            reasons.append("replay_nonce")

    reason_codes = list(dict.fromkeys(reasons))
    if reason_codes:
        return {"decision": "deny", "reason_codes": reason_codes, "oid": oid}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "oid": oid}
