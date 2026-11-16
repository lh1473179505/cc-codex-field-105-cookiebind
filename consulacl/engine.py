from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_tok(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "token_id": obj.get("token_id"),
        "ns": obj.get("ns"),
        "rules": obj.get("rules"),
        "service_prefix": obj.get("service_prefix"),
        "node": obj.get("node"),
        "nonce": obj.get("nonce"),
    }


def _signing_input(obj: dict) -> str:
    rules = obj.get("rules")
    rules_csv = ",".join(rules) if isinstance(rules, list) else ""
    parts = (
        "v1",
        obj.get("kid"),
        obj.get("token_id"),
        obj.get("ns"),
        rules_csv,
        obj.get("service_prefix"),
        obj.get("node"),
        obj.get("iat"),
        obj.get("nonce"),
    )
    return "|".join("" if part is None else str(part) for part in parts)


def _signature_valid(secret_hex: str, signing_input: str, sig_b64: Any) -> bool:
    if not isinstance(sig_b64, str):
        return False
    try:
        padded = sig_b64 + "=" * (-len(sig_b64) % 4)
        provided = base64.urlsafe_b64decode(padded.encode("ascii"))
        expected = hmac.new(
            bytes.fromhex(secret_hex),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(provided, expected)


def admit_tok(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    token_id = obj.get("token_id")
    reasons: list[str] = []

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if key_entry is None:
        reasons.append("unknown_kid")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    if key_entry is not None and not _signature_valid(
        key_entry.get("secret", ""), _signing_input(obj), obj.get("sig")
    ):
        reasons.append("bad_signature")

    if not isinstance(token_id, str) or len(token_id) != policy.get("token_id_len"):
        reasons.append("token_id_len")

    ns_name = obj.get("ns")
    ns_policy = policy.get("namespaces", {}).get(ns_name)
    if ns_policy is None:
        reasons.append("ns_not_allowed")

    rules = obj.get("rules")
    rules = rules if isinstance(rules, list) else []
    forbid_rules = set(policy.get("forbid_rules", ()))
    if ns_policy is not None:
        rules_max = set(ns_policy.get("rules_max", ()))
        if any(rule not in rules_max for rule in rules):
            reasons.append("rules_exceed_max")
    if any(rule in forbid_rules for rule in rules):
        reasons.append("rule_forbidden")

    if ns_policy is not None:
        if obj.get("service_prefix") not in ns_policy.get("service_prefixes", ()):
            reasons.append("service_prefix_denied")
        if obj.get("node") not in ns_policy.get("nodes", ()):
            reasons.append("node_denied")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_invalid")
    else:
        age = now_unix - iat
        if age < -int(policy.get("clock_skew_seconds", 0)) or age > int(
            policy.get("max_age_seconds", 0)
        ):
            reasons.append("time_window")

    nonce = obj.get("nonce")
    if nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "token_id": token_id}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "token_id": token_id}
