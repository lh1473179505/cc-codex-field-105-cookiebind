from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any
from urllib.parse import urlsplit


_REQUIRED_FIELDS = (
    "kid",
    "uri",
    "suite",
    "component",
    "signed_by",
    "arch",
    "nonce",
    "iat",
    "sig",
)


def _deny(uri: Any, *reason_codes: str) -> dict:
    return {"decision": "deny", "reason_codes": list(reason_codes), "uri": uri}


def _signing_input(obj: dict) -> str:
    return "v1|{kid}|{uri}|{suite}|{component}|{signed_by}|{arch}|{iat}|{nonce}".format(
        kid=obj["kid"],
        uri=obj["uri"],
        suite=obj["suite"],
        component=obj["component"],
        signed_by=obj["signed_by"],
        arch=obj["arch"],
        iat=obj["iat"],
        nonce=obj["nonce"],
    )


def _encode_sig(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _uri_allowed(uri: str, policy: dict) -> bool:
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return False
    if parsed.scheme not in policy.get("allowed_schemes", []):
        return False
    if parsed.scheme == "http" and policy.get("forbid_http"):
        return False
    hostname = parsed.hostname
    if not hostname or hostname not in policy.get("allowed_hosts", []):
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    for bad in policy.get("uri_deny_substrings", []):
        if bad and bad in uri:
            return False
    return True


def admit_repo(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    uri = obj.get("uri")

    if not isinstance(obj, dict) or any(
        obj.get(field) is None for field in _REQUIRED_FIELDS
    ):
        return _deny(uri, "malformed_repo")

    if not isinstance(obj["uri"], str) or not _uri_allowed(obj["uri"], policy):
        return _deny(uri, "uri_denied")

    suites = policy.get("suites", {})
    if obj["suite"] not in suites:
        return _deny(uri, "suite_denied")
    if obj["component"] not in suites.get(obj["suite"], []):
        return _deny(uri, "component_denied")

    if obj["signed_by"] not in policy.get("signed_by_allow", []):
        return _deny(uri, "signed_by_denied")
    if obj["arch"] not in policy.get("arch_allow", []):
        return _deny(uri, "arch_denied")

    key = keys.get("keys", {}).get(obj["kid"])
    if not isinstance(key, dict):
        return _deny(uri, "unknown_kid")
    if key.get("status") != "active":
        return _deny(uri, "key_revoked")

    try:
        secret = bytes.fromhex(key["secret"])
    except (KeyError, TypeError, ValueError):
        return _deny(uri, "bad_key_config")

    digest = hmac.new(
        secret, _signing_input(obj).encode("utf-8"), hashlib.sha256
    ).digest()
    if not hmac.compare_digest(_encode_sig(digest), str(obj["sig"])):
        return _deny(uri, "bad_signature")

    iat = obj["iat"]
    if not isinstance(iat, int) or isinstance(iat, bool):
        return _deny(uri, "bad_iat")
    age = now_unix - iat
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if age > max_age or age < -skew:
        return _deny(uri, "iat_out_of_window")

    items = store.setdefault("items", {})
    if obj["nonce"] in items:
        return _deny(uri, "nonce_replayed")

    items[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "uri": obj["uri"]}

def inspect_repo(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "uri": obj.get("uri"),
        "suite": obj.get("suite"),
        "component": obj.get("component"),
        "signed_by": obj.get("signed_by"),
        "arch": obj.get("arch"),
        "nonce": obj.get("nonce"),
    }
