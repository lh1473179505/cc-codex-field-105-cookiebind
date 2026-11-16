from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_result(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "tool": obj.get("tool"),
        "rule_id": obj.get("rule_id"),
        "level": obj.get("level"),
        "uri": obj.get("uri"),
        "start_line": obj.get("start_line"),
        "end_line": obj.get("end_line"),
        "fingerprints": obj.get("fingerprints"),
        "nonce": obj.get("nonce"),
    }


def _deny(obj: dict, reason: str) -> dict:
    return {"decision": "deny", "reason_codes": [reason], "rule_id": obj.get("rule_id") or ""}


def _uri_violation(uri: Any, prefixes: list[str], deny_substrings: list[str]) -> str | None:
    if not isinstance(uri, str) or uri == "":
        return "uri_invalid"
    if any(bad in uri for bad in deny_substrings):
        return "uri_unsafe"
    if uri.startswith("/") or (len(uri) >= 2 and uri[1] == ":"):
        return "uri_unsafe"
    components = uri.split("/")
    if any(component == "" or component == "." or component == ".." for component in components):
        return "uri_unsafe"
    if not any(uri.startswith(prefix) for prefix in prefixes):
        return "uri_prefix_mismatch"
    return None


def _region_violation(start: Any, end: Any, line_min: int, line_max: int) -> str | None:
    if not isinstance(start, int) or isinstance(start, bool) or \
       not isinstance(end, int) or isinstance(end, bool):
        return "region_invalid"
    if not (line_min <= start <= line_max) or not (line_min <= end <= line_max):
        return "region_invalid"
    if start > end:
        return "region_order"
    return None


def _fingerprint_violation(fingerprints: Any, tool_policy: dict, policy: dict) -> str | None:
    if not isinstance(fingerprints, dict) or not fingerprints:
        return "fingerprint_invalid"
    allowed = policy.get("allowed_fingerprint_keys", [])
    min_len = policy.get("fingerprint_value_min_len", 0)
    max_len = policy.get("fingerprint_value_max_len", 0)
    for key, value in fingerprints.items():
        if key not in allowed:
            return "fingerprint_key_not_allowed"
        if not isinstance(value, str) or not (min_len <= len(value) <= max_len):
            return "fingerprint_value_length"
    for required in tool_policy.get("required_fingerprints", []):
        if required not in fingerprints:
            return "fingerprint_required_missing"
    return None


def _canonical_line(obj: dict) -> str:
    fingerprints = obj["fingerprints"]
    encoded = ",".join(f"{key}={fingerprints[key]}" for key in sorted(fingerprints))
    return "|".join([
        "v1",
        str(obj["kid"]),
        str(obj["tool"]),
        str(obj["rule_id"]),
        str(obj["level"]),
        str(obj["uri"]),
        str(obj["start_line"]),
        str(obj["end_line"]),
        encoded,
        str(obj["iat"]),
        str(obj["nonce"]),
    ])


def _expected_signature(secret_hex: str, line: str) -> str | None:
    try:
        key = bytes.fromhex(secret_hex)
    except ValueError:
        return None
    digest = hmac.new(key, line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def admit_result(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store shape")

    rule_id = obj.get("rule_id") or ""

    tool_name = obj.get("tool")
    tool_policy = policy.get("tools", {}).get(tool_name)
    if not isinstance(tool_policy, dict):
        return _deny(obj, "unknown_tool")

    levels = tool_policy.get("rules", {}).get(obj.get("rule_id"))
    if not isinstance(levels, list):
        return _deny(obj, "unknown_rule")
    if obj.get("level") not in levels:
        return _deny(obj, "level_not_allowed")

    reason = _uri_violation(
        obj.get("uri"),
        tool_policy.get("uri_prefixes", []),
        policy.get("uri_deny_substrings", []),
    )
    if reason is not None:
        return _deny(obj, reason)

    reason = _region_violation(
        obj.get("start_line"),
        obj.get("end_line"),
        policy.get("line_min", 1),
        policy.get("line_max", 200000),
    )
    if reason is not None:
        return _deny(obj, reason)

    reason = _fingerprint_violation(obj.get("fingerprints"), tool_policy, policy)
    if reason is not None:
        return _deny(obj, reason)

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if not isinstance(key_entry, dict):
        return _deny(obj, "unknown_key")
    if key_entry.get("status") != "active":
        return _deny(obj, "key_revoked")

    expected = _expected_signature(str(key_entry.get("secret", "")), _canonical_line(obj))
    provided = obj.get("sig")
    if expected is None or not isinstance(provided, str) or \
       not hmac.compare_digest(expected, provided):
        return _deny(obj, "bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return _deny(obj, "iat_invalid")
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if iat > now_unix + skew or iat < now_unix - max_age:
        return _deny(obj, "iat_outside_window")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or nonce == "":
        return _deny(obj, "nonce_invalid")
    if nonce in store["items"]:
        return _deny(obj, "nonce_replay")

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "rule_id": rule_id}
