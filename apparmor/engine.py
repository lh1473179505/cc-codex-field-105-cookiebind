from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

RULE_RE = re.compile(r"(/\S+) (\S+),")

def inspect_profile(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "name": obj.get("name"),
        "path": obj.get("path"),
        "rules": obj.get("rules"),
        "mode": obj.get("mode"),
        "capabilities": obj.get("capabilities"),
        "network": obj.get("network"),
        "nonce": obj.get("nonce"),
    }

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _is_str_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)

def _check_rules(obj: dict, profile: dict, policy: dict, reason: list) -> None:
    rules = obj.get("rules")
    if not _is_str_list(rules):
        reason.append("rule_syntax")
        return
    count_min = policy.get("rule_count_min", 0)
    count_max = policy.get("rule_count_max", len(rules))
    if not (count_min <= len(rules) <= count_max):
        reason.append("rule_count")
    if policy.get("require_unique_rules", False) and len(rules) != len(set(rules)):
        reason.append("rule_duplicate")
    deny_substrings = policy.get("path_deny_substrings", [])
    prefixes = profile.get("path_prefixes", [])
    permissions = profile.get("permissions", [])
    for rule in rules:
        match = RULE_RE.fullmatch(rule)
        if match is None:
            reason.append("rule_syntax")
            continue
        rule_path, perm_string = match.group(1), match.group(2)
        components = rule_path.split("/")
        if (any(sub in rule_path for sub in deny_substrings)
                or any(component in (".", "..") for component in components)):
            reason.append("rule_path_denied")
            continue
        if not any(rule_path.startswith(prefix) for prefix in prefixes):
            reason.append("rule_prefix")
            continue
        if not perm_string or any(char not in permissions for char in perm_string):
            reason.append("rule_permission")

def _check_capabilities(obj: dict, profile: dict, reason: list) -> None:
    capabilities = obj.get("capabilities")
    if not _is_str_list(capabilities):
        reason.append("capability_denied")
        return
    allowed = profile.get("capabilities", [])
    if len(capabilities) != len(set(capabilities)):
        reason.append("capability_duplicate")
    if any(item not in allowed for item in capabilities):
        reason.append("capability_denied")
    if not capabilities and allowed:
        reason.append("capability_denied")

def _check_network(obj: dict, profile: dict, reason: list) -> None:
    network = obj.get("network")
    if not _is_str_list(network):
        reason.append("network_denied")
        return
    allowed = profile.get("network", [])
    if len(network) != len(set(network)):
        reason.append("network_duplicate")
    if any(item not in allowed for item in network):
        reason.append("network_denied")

def _expected_signature(obj: dict, secret_hex: str) -> str:
    message = "|".join([
        "v1",
        str(obj["kid"]),
        str(obj["name"]),
        str(obj["path"]),
        ",".join(obj["rules"]),
        str(obj["mode"]),
        ",".join(obj["capabilities"]),
        ",".join(obj["network"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ])
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        message.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url(digest)

def _check_key_and_signature(obj: dict, keys: dict, reason: list) -> None:
    kid = obj.get("kid")
    entry = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if entry is None:
        reason.append("unknown_key")
        return
    if entry.get("status") != "active":
        reason.append("key_revoked")
    fields_ready = (
        _is_str_list(obj.get("rules"))
        and _is_str_list(obj.get("capabilities"))
        and _is_str_list(obj.get("network"))
        and isinstance(obj.get("nonce"), str)
        and isinstance(obj.get("iat"), int)
        and not isinstance(obj.get("iat"), bool)
    )
    if not fields_ready:
        reason.append("bad_signature")
        return
    expected = _expected_signature(obj, entry["secret"])
    if not hmac.compare_digest(expected, str(obj.get("sig", ""))):
        reason.append("bad_signature")

def _check_iat(obj: dict, policy: dict, now_unix: int, reason: list) -> None:
    iat = obj.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int):
        reason.append("iat_window")
        return
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if not (now_unix - max_age - skew <= iat <= now_unix + skew):
        reason.append("iat_window")

def admit_profile(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    name = obj.get("name")
    reason: list = []
    profile = policy.get("profiles", {}).get(name) if isinstance(name, str) else None
    if profile is None:
        reason.append("unknown_profile")
    else:
        if obj.get("path") != profile.get("path"):
            reason.append("profile_path_mismatch")
        _check_rules(obj, profile, policy, reason)
        if obj.get("mode") != profile.get("mode"):
            reason.append("mode_mismatch")
        _check_capabilities(obj, profile, reason)
        _check_network(obj, profile, reason)
    _check_key_and_signature(obj, keys, reason)
    _check_iat(obj, policy, now_unix, reason)
    nonce = obj.get("nonce")
    if isinstance(nonce, str) and nonce in store.get("items", {}):
        reason.append("nonce_replay")
    if reason:
        return {"decision": "deny", "reason_codes": reason, "name": name}
    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "name": name}
