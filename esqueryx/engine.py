from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_q(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "index": obj.get("index"),
        "user": obj.get("user"),
        "qtype": obj.get("qtype"),
        "fields": obj.get("fields"),
        "nonce": obj.get("nonce"),
    }


def _report(index: Any, *reason_codes: str) -> dict:
    return {"decision": "deny", "reason_codes": list(reason_codes), "index": index}


def _index_allowed(index: str, patterns: list) -> bool:
    for pattern in patterns:
        if not isinstance(pattern, str):
            continue
        if pattern.endswith("*"):
            if index.startswith(pattern[:-1]):
                return True
        elif index == pattern:
            return True
    return False


def _signing_string(obj: dict) -> str:
    return "v1|{}|{}|{}|{}|{}|{}|{}".format(
        obj["kid"],
        obj["index"],
        obj["user"],
        obj["qtype"],
        obj["fields"],
        obj["iat"],
        obj["nonce"],
    )


def _key_bytes(secret: Any) -> bytes:
    if isinstance(secret, str):
        try:
            return bytes.fromhex(secret)
        except ValueError:
            return secret.encode("utf-8")
    return str(secret).encode("utf-8")


def admit_q(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    if not isinstance(obj, dict):
        return _report(None, "malformed")

    index = obj.get("index")
    str_fields = ("kid", "index", "user", "qtype", "fields", "nonce", "sig")
    if any(not isinstance(obj.get(name), str) or not obj.get(name) for name in str_fields):
        return _report(index, "malformed")
    if not isinstance(obj.get("iat"), int) or isinstance(obj.get("iat"), bool):
        return _report(index, "malformed")

    for bad in policy.get("index_deny_substrings", []):
        if isinstance(bad, str) and bad and bad in index:
            return _report(index, "index_path_unsafe")

    users = policy.get("users", {})
    user_cfg = users.get(obj["user"])
    if not isinstance(user_cfg, dict):
        return _report(index, "user_denied")

    if not _index_allowed(index, user_cfg.get("indices", [])):
        return _report(index, "index_denied")

    qtype = obj["qtype"]
    if qtype in policy.get("forbid_qtypes", []) or qtype not in user_cfg.get("qtypes", []):
        return _report(index, "qtype_denied")

    allowed_fields = set(user_cfg.get("field_allow", []))
    requested_fields = obj["fields"].split(",")
    if not requested_fields or any(
        not field or field not in allowed_fields for field in requested_fields
    ):
        return _report(index, "field_denied")

    key_cfg = keys.get("keys", {}).get(obj["kid"])
    if not isinstance(key_cfg, dict):
        return _report(index, "key_unknown")
    if key_cfg.get("status") != "active":
        return _report(index, "key_revoked")

    digest = hmac.new(
        _key_bytes(key_cfg.get("secret")),
        _signing_string(obj).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    expected_sig = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(expected_sig, obj["sig"]):
        return _report(index, "bad_signature")

    iat = obj["iat"]
    if iat < now_unix - policy.get("max_age_seconds", 0):
        return _report(index, "iat_expired")
    if iat > now_unix + policy.get("clock_skew_seconds", 0):
        return _report(index, "iat_future")

    nonce = obj["nonce"]
    if nonce in store.get("items", {}):
        return _report(index, "nonce_replayed")

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "index": index}
