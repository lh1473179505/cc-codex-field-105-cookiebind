from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_unlock(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "lock_id": obj.get("lock_id"),
        "workspace": obj.get("workspace"),
        "backend": obj.get("backend"),
        "who": obj.get("who"),
        "nonce": obj.get("nonce"),
    }


def _deny(reason: str, workspace: Any) -> dict:
    return {
        "decision": "deny",
        "reason_codes": [reason],
        "workspace": workspace if isinstance(workspace, str) else "",
    }


def _signing_input(obj: dict) -> str:
    return "v1|{kid}|{lock_id}|{workspace}|{backend}|{who}|{iat}|{nonce}".format(**obj)


def admit_unlock(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    if not isinstance(obj, dict):
        return _deny("malformed", "")

    workspace = obj.get("workspace")
    required = ("kid", "lock_id", "workspace", "backend", "who", "iat", "nonce", "sig")
    if any(not isinstance(obj.get(field), str) for field in required if field != "iat"):
        return _deny("malformed", workspace)
    if not isinstance(obj.get("iat"), int) or isinstance(obj.get("iat"), bool):
        return _deny("malformed", workspace)
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        return _deny("store_shape", workspace)

    workspaces = policy.get("workspaces", {})
    entry = workspaces.get(workspace)
    if not isinstance(entry, dict):
        return _deny("workspace_unknown", workspace)

    if obj["backend"] not in entry.get("backends", []):
        return _deny("backend_denied", workspace)
    if obj["who"] not in entry.get("owners", []):
        return _deny("who_denied", workspace)

    lock_id = obj["lock_id"]
    if len(lock_id) != policy.get("lock_id_hex_len") or not lock_id:
        return _deny("lock_id_len", workspace)
    try:
        bytes.fromhex(lock_id)
    except ValueError:
        return _deny("lock_id_hex", workspace)

    for bad in policy.get("backend_deny_substrings", []):
        if bad in obj["backend"]:
            return _deny("backend_deny_substring", workspace)

    key_entry = keys.get("keys", {}).get(obj["kid"])
    if not isinstance(key_entry, dict):
        return _deny("key_unknown", workspace)
    if key_entry.get("status") != "active":
        return _deny("key_revoked", workspace)

    try:
        secret = bytes.fromhex(key_entry["secret"])
    except (KeyError, TypeError, ValueError):
        return _deny("key_malformed", workspace)

    digest = hmac.new(secret, _signing_input(obj).encode("utf-8"), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if not hmac.compare_digest(expected, obj["sig"]):
        return _deny("bad_signature", workspace)

    iat = obj["iat"]
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if iat - now_unix > skew:
        return _deny("iat_future", workspace)
    if now_unix - iat > max_age:
        return _deny("iat_expired", workspace)

    nonce = obj["nonce"]
    if nonce in store["items"]:
        return _deny("nonce_replay", workspace)

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "workspace": workspace}
