from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_order(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "account": obj.get("account"),
        "identifiers": obj.get("identifiers"),
        "challenge": obj.get("challenge"),
        "key_auth_sha256": obj.get("key_auth_sha256"),
        "contact": obj.get("contact"),
        "wildcard": obj.get("wildcard"),
        "nonce": obj.get("nonce"),
    }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_lowercase_hex(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def _identifier_has_wildcard(identifier: Any) -> bool:
    return isinstance(identifier, str) and identifier.startswith("*.")


def _identifier_shape_ok(identifier: Any) -> bool:
    if not isinstance(identifier, str) or not identifier:
        return False
    # Only DNS labels; uppercase names are rejected outright.
    if any(("A" <= ch <= "Z") for ch in identifier):
        return False
    if "*" in identifier:
        # Exactly one leading "*." and no other wildcard character.
        if not identifier.startswith("*.") or "*" in identifier[2:]:
            return False
        labels = identifier[2:].split(".")
    else:
        labels = identifier.split(".")
    return all(label != "" for label in labels)


def _identifier_matches_suffix(identifier: str, suffixes: list) -> bool:
    name = identifier[2:] if identifier.startswith("*.") else identifier
    for suffix in suffixes:
        if not isinstance(suffix, str):
            continue
        if name == suffix or name.endswith("." + suffix):
            return True
    return False


def _recompute_sig(obj: dict, keys: dict) -> str | None:
    kid = obj.get("kid")
    entry = keys.get(kid) if isinstance(keys, dict) else None
    if not isinstance(entry, dict) or not isinstance(entry.get("secret"), str):
        return None
    try:
        secret = bytes.fromhex(entry["secret"])
    except ValueError:
        return None
    identifiers = obj.get("identifiers")
    id_str = ",".join(identifiers) if isinstance(identifiers, list) else ""
    line = "|".join([
        "v1",
        str(obj.get("kid", "")),
        str(obj.get("account", "")),
        id_str,
        str(obj.get("challenge", "")),
        str(obj.get("key_auth_sha256", "")),
        str(obj.get("contact", "")),
        str(obj.get("wildcard", "")),
        str(obj.get("iat", "")),
        str(obj.get("nonce", "")),
    ])
    digest = hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def admit_order(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    account = obj.get("account")
    report = {"decision": "deny", "reason_codes": reasons, "account": account}

    accounts = policy.get("accounts", {}) if isinstance(policy, dict) else {}
    acct = accounts.get(account) if isinstance(accounts, dict) else None
    if not isinstance(acct, dict):
        reasons.append("unknown_account")
        return report

    identifiers = obj.get("identifiers")
    if not isinstance(identifiers, list) or not identifiers:
        reasons.append("bad_identifiers")
        return report

    # Shape: no empty labels, no uppercase, at most one leading wildcard.
    if not all(_identifier_shape_ok(identifier) for identifier in identifiers):
        reasons.append("bad_identifier_shape")

    # Duplicates are rejected.
    if len(set(identifiers)) != len(identifiers):
        reasons.append("duplicate_identifier")

    # Identifier count cap.
    max_identifiers = policy.get("max_identifiers")
    if _is_int(max_identifiers) and len(identifiers) > max_identifiers:
        reasons.append("too_many_identifiers")

    wildcard_present = any(_identifier_has_wildcard(identifier) for identifier in identifiers)
    wildcard_flag = obj.get("wildcard")
    if not _is_int(wildcard_flag) or wildcard_flag not in (0, 1):
        reasons.append("bad_wildcard_flag")
    elif policy.get("wildcard_flag_must_match", True) and bool(wildcard_flag) != wildcard_present:
        reasons.append("wildcard_flag_mismatch")

    # Mixed wildcard/non-wildcard orders are forbidden when configured.
    non_wildcard_present = any(
        isinstance(identifier, str) and not _identifier_has_wildcard(identifier)
        for identifier in identifiers
    )
    if policy.get("forbid_mixed_wildcard", False) and wildcard_present and non_wildcard_present:
        reasons.append("mixed_wildcard")

    # Suffix boundary: exact suffix match or a subdomain separated by a dot.
    suffixes = acct.get("identifier_suffixes", [])
    if not isinstance(suffixes, list) or not all(
        _identifier_matches_suffix(identifier, suffixes)
        for identifier in identifiers
        if isinstance(identifier, str)
    ):
        reasons.append("identifier_suffix_denied")

    # Challenge must belong to the account; wildcard orders force dns-01.
    challenge = obj.get("challenge")
    allowed_challenges = acct.get("challenges", [])
    if not isinstance(allowed_challenges, list) or challenge not in allowed_challenges:
        reasons.append("challenge_not_allowed")
    if wildcard_present and policy.get("require_dns_for_wildcard", True) and challenge != "dns-01":
        reasons.append("wildcard_requires_dns01")

    # Contact is bound to the account.
    if obj.get("contact") != acct.get("contact"):
        reasons.append("contact_mismatch")

    # key authorization digest: exact length, lowercase hex only.
    digest = obj.get("key_auth_sha256")
    expected_len = policy.get("key_auth_hex_len", 64)
    if not isinstance(digest, str) or len(digest) != expected_len:
        reasons.append("key_auth_bad_length")
    elif policy.get("require_lowercase_hex", True) and not _is_lowercase_hex(digest):
        reasons.append("key_auth_not_lowercase_hex")

    # HMAC binding over the full signature contract.
    expected_sig = _recompute_sig(obj, keys.get("keys", {}) if isinstance(keys, dict) else {})
    sig = obj.get("sig")
    if expected_sig is None or not isinstance(sig, str) or not hmac.compare_digest(expected_sig, sig):
        reasons.append("bad_signature")

    # Key status is checked only against a recognized key.
    key_entry = None
    key_bag = keys.get("keys", {}) if isinstance(keys, dict) else {}
    if isinstance(key_bag, dict):
        key_entry = key_bag.get(obj.get("kid"))
    if not isinstance(key_entry, dict):
        reasons.append("unknown_key")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    # Time window: no future beyond skew, no older than max age.
    iat = obj.get("iat")
    if not _is_int(iat):
        reasons.append("bad_iat")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat - now_unix > skew:
            reasons.append("iat_in_future")
        if now_unix - iat > max_age:
            reasons.append("iat_too_old")

    # Nonce replay is decided before any store mutation.
    nonce = obj.get("nonce")
    items = store.get("items") if isinstance(store, dict) else None
    if not isinstance(nonce, str) or not nonce:
        reasons.append("bad_nonce")
    elif not isinstance(items, dict) or nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return report

    # Allow is the only path that consumes the nonce.
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "account": account}
