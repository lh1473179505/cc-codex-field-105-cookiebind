from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any


_FIELDS = ("kid", "aud", "ns", "sa", "path", "bound", "iat", "exp", "nonce", "sig")


def _signing_input(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj["kid"]),
        str(obj["aud"]),
        str(obj["ns"]),
        str(obj["sa"]),
        str(obj["path"]),
        str(obj["bound"]),
        str(obj["iat"]),
        str(obj["exp"]),
        str(obj["nonce"]),
    ])


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def inspect_token(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "aud": obj.get("aud"),
        "ns": obj.get("ns"),
        "sa": obj.get("sa"),
        "path": obj.get("path"),
        "bound": obj.get("bound"),
        "nonce": obj.get("nonce"),
    }

def admit_token(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    sa = obj.get("sa") if isinstance(obj, dict) else None

    def deny(reason: str) -> dict:
        return {"decision": "deny", "reason_codes": [reason], "sa": sa}

    if not isinstance(obj, dict) or any(obj.get(field) is None for field in _FIELDS):
        return deny("malformed_token")

    # Path safety first: reject traversal/encoding tricks before any prefix allow.
    path = obj["path"]
    if not isinstance(path, str) or any(
        token in path for token in policy.get("path_deny_substrings", ("..", "%2e", "%2E", "//"))
    ):
        return deny("path_unsafe")

    # Gate 1: HMAC signature and key revocation.
    key_entry = keys.get("keys", {}).get(obj["kid"])
    try:
        secret = bytes.fromhex(key_entry["secret"]) if key_entry else b""
    except (TypeError, ValueError):
        secret = b""
    digest = hmac.new(secret, _signing_input(obj).encode("utf-8"), hashlib.sha256).digest()
    if not key_entry or not hmac.compare_digest(_b64url(digest), str(obj["sig"])):
        return deny("bad_sig")
    if key_entry.get("status") == "revoked":
        return deny("kid_revoked")

    # Gate 2: audience / namespace / service-account whitelist (sa keyed by ns).
    if obj["aud"] not in policy.get("allowed_audiences", []):
        return deny("aud_denied")
    ns = obj["ns"]
    if ns not in policy.get("allowed_namespaces", []):
        return deny("ns_denied")
    if obj["sa"] not in policy.get("sa_allow", {}).get(ns, []):
        return deny("sa_denied")

    # Gate 3: path must stay under an allowed prefix after the safety check.
    if not any(path.startswith(prefix) for prefix in policy.get("path_allow_prefixes", [])):
        return deny("path_denied")

    # Gate 4: bound object Kind/ns/name, Kind allowed and ns pinned to token ns.
    if policy.get("require_bound", False):
        parts = str(obj["bound"]).split("/")
        if len(parts) != 3 or not all(parts):
            return deny("bound_invalid")
        bound_kind, bound_ns, _bound_name = parts
        if bound_kind not in policy.get("bound_kinds", ()) or bound_ns != ns:
            return deny("bound_invalid")

    # Gate 5: time window.
    try:
        iat = int(obj["iat"])
        exp = int(obj["exp"])
    except (TypeError, ValueError):
        return deny("malformed_token")
    skew = int(policy.get("clock_skew_seconds", 0))
    if now_unix + skew < iat:
        return deny("not_valid_yet")
    if now_unix >= exp:
        return deny("token_expired")
    if now_unix - iat > int(policy.get("max_age_seconds", 0)) + skew:
        return deny("max_age_exceeded")

    # Gate 6: nonce anti-replay; the store is written only on allow.
    nonce = str(obj["nonce"])
    if nonce in store.get("items", {}):
        return deny("nonce_replayed")
    store["items"][nonce] = {"ts": now_unix}

    return {"decision": "allow", "reason_codes": [], "sa": sa}
