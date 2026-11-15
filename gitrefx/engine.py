from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_update(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "ref": obj.get("ref"),
        "old_oid": obj.get("old_oid"),
        "new_oid": obj.get("new_oid"),
        "actor": obj.get("actor"),
        "force": obj.get("force"),
        "nonce": obj.get("nonce"),
    }

def _report(decision: str, reason_codes: list[str], ref: Any) -> dict:
    return {"decision": decision, "reason_codes": reason_codes, "ref": ref}


def _deny(reason: str, ref: Any) -> dict:
    return _report("deny", [reason], ref)


def _is_hex_oid(value: Any, length: int) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _signing_input(obj: dict) -> str:
    force_flag = "1" if obj.get("force") else "0"
    return "|".join([
        "v1",
        str(obj.get("kid", "")),
        str(obj.get("ref", "")),
        str(obj.get("old_oid", "")),
        str(obj.get("new_oid", "")),
        str(obj.get("actor", "")),
        force_flag,
        str(obj.get("iat", "")),
        str(obj.get("nonce", "")),
    ])


def admit_update(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    ref = obj.get("ref")

    # Ref normalize / safety: unsafe syntax is rejected before any name checks.
    if not isinstance(ref, str) or ".." in ref or "//" in ref:
        return _deny("ref_unsafe", ref)
    if not any(ref.startswith(prefix) for prefix in policy["allowed_ref_prefixes"]):
        return _deny("ref_prefix_denied", ref)
    if ref in policy["denied_ref_names"]:
        return _deny("ref_name_denied", ref)

    # Gate 1: HMAC + revocation + actor whitelist.
    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if key_entry is None:
        return _deny("kid_unknown", ref)
    if key_entry.get("status") == "revoked":
        return _deny("kid_revoked", ref)
    secret = bytes.fromhex(key_entry["secret"])
    digest = hmac.new(secret, _signing_input(obj).encode("utf-8"), hashlib.sha256).digest()
    expected_sig = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    if not isinstance(obj.get("sig"), str) or not hmac.compare_digest(expected_sig, obj["sig"]):
        return _deny("bad_sig", ref)
    if obj.get("actor") not in policy["actors"]:
        return _deny("actor_denied", ref)

    # Gate 2: oid shape and delete prohibition.
    oid_len = policy["oid_hex_len"]
    if not _is_hex_oid(obj.get("old_oid"), oid_len) or not _is_hex_oid(obj.get("new_oid"), oid_len):
        return _deny("oid_bad", ref)
    if policy.get("forbid_delete") and set(obj["new_oid"]) == {"0"}:
        return _deny("delete_forbidden", ref)

    # Gate 3: force on protected prefixes is restricted to selected actors.
    if obj.get("force") and any(ref.startswith(prefix) for prefix in policy["protect_prefixes"]):
        if obj.get("actor") not in policy["force_require_actors"]:
            return _deny("force_denied", ref)

    # Gate 4: time window and allow-only nonce tracking.
    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return _deny("iat_bad", ref)
    skew = policy["clock_skew_seconds"]
    max_age = policy["max_age_seconds"]
    if iat < now_unix - max_age:
        return _deny("iat_expired", ref)
    if iat > now_unix + skew:
        return _deny("iat_future", ref)
    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return _deny("nonce_invalid", ref)
    if nonce in store.setdefault("items", {}):
        return _deny("nonce_replay", ref)

    store["items"][nonce] = {"ts": now_unix}
    return _report("allow", [], ref)
