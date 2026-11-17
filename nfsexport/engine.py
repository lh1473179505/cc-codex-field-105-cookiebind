from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

def inspect_export(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "export_path": obj.get("export_path"),
        "root_squash": obj.get("root_squash"),
        "client_cidr": obj.get("client_cidr"),
        "permissions": obj.get("permissions"),
        "anon_uid": obj.get("anon_uid"),
        "anon_gid": obj.get("anon_gid"),
        "nonce": obj.get("nonce"),
    }

def _canonical_path(path: Any) -> bool:
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    if "\\" in path or "\x00" in path:
        return False
    if path != "/" and path.endswith("/"):
        return False
    parts = path.split("/")
    for part in parts[1:]:
        if part in ("", ".", ".."):
            return False
    return True

def _signing_payload(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("export_path")),
        str(obj.get("root_squash")),
        str(obj.get("client_cidr")),
        ",".join(obj.get("permissions") or []),
        str(obj.get("anon_uid")),
        str(obj.get("anon_gid")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _expected_sig(secret_hex: str, obj: dict) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        _signing_payload(obj).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def admit_export(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    export_path = obj.get("export_path")

    export_cfg = None
    if not _canonical_path(export_path):
        reasons.append("path_not_canonical")
    else:
        export_cfg = (policy.get("exports") or {}).get(export_path)
        if export_cfg is None:
            reasons.append("path_not_registered")

    if export_cfg is not None:
        if obj.get("root_squash") != export_cfg.get("root_squash"):
            reasons.append("root_squash_mismatch")
        if obj.get("anon_uid") != export_cfg.get("anon_uid"):
            reasons.append("anon_uid_mismatch")
        if obj.get("anon_gid") != export_cfg.get("anon_gid"):
            reasons.append("anon_gid_mismatch")

        cidr = obj.get("client_cidr")
        network = None
        if not isinstance(cidr, str):
            reasons.append("client_cidr_invalid")
        else:
            try:
                network = ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                reasons.append("client_cidr_invalid")
        if network is not None:
            if str(network) != cidr:
                reasons.append("client_cidr_not_canonical")
            if policy.get("forbid_default_route") and network.prefixlen == 0:
                reasons.append("client_cidr_default_route")
            supernets = []
            for sup in export_cfg.get("client_supernets") or []:
                try:
                    supernets.append(ipaddress.ip_network(sup, strict=True))
                except ValueError:
                    continue
            if not any(network.subnet_of(sup) for sup in supernets):
                reasons.append("client_cidr_not_allowed")

        perms = obj.get("permissions")
        if not isinstance(perms, list) or not all(isinstance(p, str) for p in perms):
            reasons.append("permissions_invalid")
        else:
            if policy.get("require_unique_permissions") and len(set(perms)) != len(perms):
                reasons.append("permissions_not_unique")
            allowed = set(export_cfg.get("permissions_allowed") or [])
            required = set(export_cfg.get("permissions_required") or [])
            if not set(perms) <= allowed:
                reasons.append("permissions_not_allowed")
            if not required <= set(perms):
                reasons.append("permissions_required_missing")

    kid = obj.get("kid")
    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("key_unknown")
    else:
        if key_entry.get("status") != "active":
            reasons.append("key_not_active")
        else:
            expected = _expected_sig(key_entry.get("secret", ""), obj)
            if not hmac.compare_digest(expected, str(obj.get("sig"))):
                reasons.append("sig_mismatch")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_invalid")
    else:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat > now_unix + skew:
            reasons.append("iat_in_future")
        if now_unix - iat > max_age:
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in (store.get("items") or {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "export_path": export_path}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "export_path": export_path}
