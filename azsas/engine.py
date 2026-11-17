from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any


def inspect_sas(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "account": obj.get("account"),
        "service": obj.get("service"),
        "resource": obj.get("resource"),
        "path": obj.get("path"),
        "permissions": obj.get("permissions"),
        "expiry": obj.get("expiry"),
        "source_ip": obj.get("source_ip"),
        "https": obj.get("https"),
        "nonce": obj.get("nonce"),
    }


def _sig_line(obj: dict) -> str:
    return "v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(
        obj["kid"],
        obj["account"],
        obj["service"],
        obj["resource"],
        obj["path"],
        ",".join(obj["permissions"]),
        obj["expiry"],
        obj["source_ip"],
        obj["https"],
        obj["iat"],
        obj["nonce"],
    )


def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


_REQUIRED_FIELDS = (
    "kid", "account", "service", "resource", "path", "permissions",
    "expiry", "source_ip", "https", "iat", "nonce", "sig",
)


def admit_sas(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    account_name = obj.get("account") if isinstance(obj, dict) else None

    def deny(code: str) -> dict:
        reasons.append(code)
        return {"decision": "deny", "reason_codes": reasons, "account": account_name}

    if not isinstance(obj, dict) or any(f not in obj for f in _REQUIRED_FIELDS):
        return deny("malformed")
    if not isinstance(obj["permissions"], list) or not all(isinstance(p, str) for p in obj["permissions"]):
        return deny("malformed")
    if not isinstance(obj["expiry"], int) or isinstance(obj["expiry"], bool):
        return deny("malformed")
    if not isinstance(obj["iat"], int) or isinstance(obj["iat"], bool):
        return deny("malformed")

    key = keys.get("keys", {}).get(obj["kid"])
    if key is None:
        return deny("unknown_key")
    if key.get("status") != "active":
        return deny("key_not_active")

    if not hmac.compare_digest(_expected_sig(key["secret"], _sig_line(obj)), str(obj["sig"])):
        return deny("bad_signature")

    accounts = policy.get("accounts", {})
    account = accounts.get(obj["account"])
    if account is None:
        return deny("unknown_account")
    service = account.get("services", {}).get(obj["service"])
    if service is None:
        return deny("unknown_service")
    resource = service.get("resources", {}).get(obj["resource"])
    if resource is None:
        return deny("unknown_resource")

    path = obj["path"]
    if not isinstance(path, str) or not path or path.startswith("/"):
        return deny("bad_path")
    for bad in policy.get("path_deny_substrings", []):
        if bad and bad in path:
            return deny("bad_path")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return deny("bad_path")
    if not any(path.startswith(prefix) for prefix in resource.get("path_prefixes", [])):
        return deny("path_prefix")

    perms = obj["permissions"]
    if policy.get("require_sorted_unique_permissions", False):
        if perms != sorted(perms) or len(set(perms)) != len(perms):
            return deny("permissions_not_sorted_unique")
    if not set(resource.get("permissions_required", [])).issubset(perms):
        return deny("permissions_required")
    if not set(perms).issubset(resource.get("permissions_allowed", [])):
        return deny("permissions_not_allowed")

    if not (resource["expiry_min"] <= obj["expiry"] <= resource["expiry_max"]):
        return deny("expiry_out_of_bounds")

    try:
        src = ipaddress.ip_address(obj["source_ip"])
    except ValueError:
        return deny("bad_source_ip")
    if not any(src in ipaddress.ip_network(cidr) for cidr in resource.get("source_cidrs", [])):
        return deny("source_ip_not_allowed")

    if obj["https"] != policy.get("require_https"):
        return deny("https_required")

    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if obj["iat"] > now_unix + skew or now_unix - obj["iat"] > max_age + skew:
        return deny("stale_iat")

    items = store.setdefault("items", {})
    if obj["nonce"] in items:
        return deny("nonce_replay")

    items[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "account": account_name}
