from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

WRITE_RIGHTS = ("write_file", "remove_file", "refer", "truncate")


def inspect_ruleset(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "abi": obj.get("abi"),
        "access_fs": obj.get("access_fs"),
        "allowed_path": obj.get("allowed_path"),
        "beneath": obj.get("beneath"),
        "read_write": obj.get("read_write"),
        "nonce": obj.get("nonce"),
    }


def _signed_line(obj: dict) -> str:
    return "v1|{}|{}|{}|{}|{}|{}|{}|{}".format(
        obj["kid"],
        obj["abi"],
        ",".join(obj["access_fs"]),
        obj["allowed_path"],
        ",".join(obj["beneath"]),
        obj["read_write"],
        obj["iat"],
        obj["nonce"],
    )


def _expected_sig(obj: dict, secret_hex: str) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex), _signed_line(obj).encode("utf-8"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _beneath_component_error(path: str) -> bool:
    if "\\" in path or "\x00" in path:
        return True
    for part in path.split("/"):
        if part in ("", ".", ".."):
            return True
    return False


def admit_ruleset(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    allowed_path = obj.get("allowed_path") if isinstance(obj, dict) else None

    def deny(code: str) -> dict:
        return {"decision": "deny", "reason_codes": [code], "allowed_path": allowed_path}

    if not isinstance(obj, dict):
        return deny("malformed")
    kid = obj.get("kid")
    abi = obj.get("abi")
    access_fs = obj.get("access_fs")
    beneath = obj.get("beneath")
    read_write = obj.get("read_write")
    nonce = obj.get("nonce")
    iat = obj.get("iat")
    sig = obj.get("sig")
    if (
        not isinstance(kid, str)
        or not isinstance(abi, int)
        or isinstance(abi, bool)
        or not isinstance(access_fs, list)
        or not access_fs
        or not all(isinstance(a, str) for a in access_fs)
        or not isinstance(allowed_path, str)
        or not isinstance(beneath, list)
        or not all(isinstance(b, str) for b in beneath)
        or read_write not in (0, 1)
        or isinstance(read_write, bool)
        or not isinstance(nonce, str)
        or not isinstance(iat, int)
        or isinstance(iat, bool)
        or not isinstance(sig, str)
    ):
        return deny("malformed")

    key_entry = keys.get("keys", {}).get(kid)
    if key_entry is None:
        return deny("unknown_kid")
    if key_entry.get("status") != "active":
        return deny("revoked")
    if not hmac.compare_digest(_expected_sig(obj, key_entry["secret"]), sig):
        return deny("bad_sig")

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if iat > now_unix + skew:
        return deny("iat_future")
    if now_unix - iat > max_age:
        return deny("iat_expired")

    items = store.get("items", {})
    if nonce in items:
        return deny("replay")

    abi_rights = policy.get("abi_access", {}).get(str(abi))
    if abi_rights is None:
        return deny("abi_unsupported")
    path_entry = policy.get("paths", {}).get(allowed_path)
    if path_entry is None:
        return deny("allowed_path")
    if not (int(path_entry["abi_min"]) <= abi <= int(path_entry["abi_max"])):
        return deny("abi_range")

    if policy.get("require_unique_access", True) and len(set(access_fs)) != len(access_fs):
        return deny("access_duplicate")
    if not set(access_fs) <= set(abi_rights):
        return deny("abi_right")
    if not set(access_fs) <= set(path_entry["access_allowed"]):
        return deny("access_profile")

    beneath_min = int(policy.get("beneath_min", 0))
    beneath_max = int(path_entry["beneath_max"])
    if not (beneath_min <= len(beneath) <= beneath_max):
        return deny("beneath_count")
    for item in beneath:
        if item.startswith("/"):
            return deny("beneath_absolute")
        if _beneath_component_error(item):
            return deny("beneath_traversal")
    if policy.get("require_unique_beneath", True) and len(set(beneath)) != len(beneath):
        return deny("beneath_duplicate")

    access_set = set(access_fs)
    if read_write == 1:
        if not {"read_file", "write_file"} <= access_set:
            return deny("read_write_right")
        prefixes = tuple(path_entry.get("rw_prefixes", []))
    else:
        if access_set & set(WRITE_RIGHTS):
            return deny("read_only_write")
        prefixes = tuple(path_entry.get("ro_prefixes", []))
    if not all(item.startswith(prefixes) for item in beneath):
        return deny("read_write_path")

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "allowed_path": allowed_path}
