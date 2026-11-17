from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

def inspect_acl(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "principal": obj.get("principal"),
        "resource": obj.get("resource"),
        "name": obj.get("name"),
        "op": obj.get("op"),
        "group": obj.get("group"),
        "client": obj.get("client"),
        "host": obj.get("host"),
        "pattern": obj.get("pattern"),
        "nonce": obj.get("nonce"),
    }

def admit_acl(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reason_codes: list[str] = []
    principal = obj.get("principal")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if not isinstance(key_entry, dict):
        reason_codes.append("key_unknown")
    else:
        if key_entry.get("status") != "active":
            reason_codes.append("key_revoked")
        secret_hex = key_entry.get("secret")
        try:
            secret = bytes.fromhex(secret_hex) if isinstance(secret_hex, str) else b""
        except ValueError:
            secret = b""
        signing_line = "v1|{}".format("|".join(
            str(obj.get(field, "")) for field in (
                "kid", "principal", "resource", "name", "op", "group",
                "client", "host", "pattern", "iat", "nonce",
            )
        ))
        try:
            digest = hmac.new(secret, signing_line.encode("utf-8"), hashlib.sha256).digest()
            expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        except (ValueError, TypeError):
            expected = ""
        if not isinstance(obj.get("sig"), str) or not hmac.compare_digest(expected, obj["sig"]):
            reason_codes.append("bad_signature")

    try:
        iat = int(obj.get("iat"))
    except (TypeError, ValueError):
        iat = None
        reason_codes.append("iat_invalid")
    if iat is not None:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat < now_unix - max_age:
            reason_codes.append("time_expired")
        if iat > now_unix + skew:
            reason_codes.append("time_future")

    principal_cfg = policy.get("principals", {}).get(principal)
    if not isinstance(principal_cfg, dict):
        reason_codes.append("principal_denied")
        principal_cfg = None

    if obj.get("resource") not in policy.get("allowed_resources", []):
        reason_codes.append("resource_denied")

    name = obj.get("name")
    if not isinstance(name, str) or not name:
        reason_codes.append("name_invalid")
    else:
        for denied in policy.get("name_deny_substrings", []):
            if denied and denied in name:
                reason_codes.append("name_deny_substring")
                break

    op = obj.get("op")
    resource = obj.get("resource")
    group = obj.get("group")
    client = obj.get("client")
    host = obj.get("host")
    pattern = obj.get("pattern")

    if principal_cfg is not None:
        if resource == "Topic":
            if not isinstance(name, str) or not any(
                name.startswith(prefix) for prefix in principal_cfg.get("topics", [])
            ):
                reason_codes.append("topic_prefix_denied")
        if op not in principal_cfg.get("ops", []):
            reason_codes.append("op_denied")
        if pattern not in principal_cfg.get("patterns", []):
            reason_codes.append("pattern_denied")
        if op in policy.get("client_required_for", []):
            if client not in principal_cfg.get("clients", []):
                reason_codes.append("client_denied")
        if policy.get("host_required", False):
            if not _host_allowed(host, principal_cfg.get("hosts", [])):
                reason_codes.append("host_denied")
        if op in policy.get("group_required_for", []):
            group_prefixes = principal_cfg.get("groups", [])
            if not isinstance(group, str) or not group or not any(
                group.startswith(prefix) for prefix in group_prefixes
            ):
                reason_codes.append("group_denied")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reason_codes.append("nonce_invalid")
    elif nonce in store.setdefault("items", {}):
        reason_codes.append("nonce_replay")

    if reason_codes:
        return {"decision": "deny", "reason_codes": reason_codes, "principal": principal}

    store["items"][nonce] = {"ts": iat}
    return {"decision": "allow", "reason_codes": [], "principal": principal}


def _host_allowed(host: Any, cidrs: list) -> bool:
    if not isinstance(host, str) or not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
