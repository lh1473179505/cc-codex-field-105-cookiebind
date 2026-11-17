from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_certificate(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "not_before": obj.get("not_before"),
        "not_after": obj.get("not_after"),
        "key_alg": obj.get("key_alg"),
        "key_bits": obj.get("key_bits"),
        "san_dns": obj.get("san_dns"),
        "eku": obj.get("eku"),
        "der_sha256": obj.get("der_sha256"),
        "nonce": obj.get("nonce"),
    }

def _canonical_message(obj: dict) -> str:
    san = ",".join(obj.get("san_dns") or [])
    eku = ",".join(obj.get("eku") or [])
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("profile")),
        str(obj.get("not_before")),
        str(obj.get("not_after")),
        str(obj.get("key_alg")),
        str(obj.get("key_bits")),
        san,
        eku,
        str(obj.get("der_sha256")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _expected_sig(secret_hex: str, obj: dict) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        _canonical_message(obj).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _san_matches_suffix(name: str, suffixes: list) -> bool:
    for suffix in suffixes:
        if name == suffix:
            return True
        if name.endswith("." + suffix):
            head = name[: -(len(suffix) + 1)]
            if head and all(label for label in head.split(".")):
                return True
    return False

def admit_certificate(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    profile_name = obj.get("profile")
    profiles = policy.get("profiles") or {}
    profile = profiles.get(profile_name)
    if profile is None:
        reasons.append("profile_unknown")
        profile = {}

    not_before = obj.get("not_before")
    not_after = obj.get("not_after")
    if not isinstance(not_before, int) or not isinstance(not_after, int):
        reasons.append("validity_type")
    elif not_before >= not_after:
        reasons.append("validity_order")
    elif profile:
        span = not_after - not_before
        if span < profile.get("validity_min_seconds", 0) or span > profile.get("validity_max_seconds", 0):
            reasons.append("validity_bounds")

    key_pairs = profile.get("key_pairs") or {}
    key_alg = obj.get("key_alg")
    key_bits = obj.get("key_bits")
    if key_alg not in key_pairs:
        reasons.append("key_alg")
    elif key_bits not in (key_pairs.get(key_alg) or []):
        reasons.append("key_bits")

    san_dns = obj.get("san_dns")
    if not isinstance(san_dns, list) or not all(isinstance(s, str) for s in san_dns):
        reasons.append("san_type")
        san_dns = []
    if profile:
        if not (profile.get("san_min", 0) <= len(san_dns) <= profile.get("san_max", 0)):
            reasons.append("san_count")
    if policy.get("require_unique_san") and len(set(san_dns)) != len(san_dns):
        reasons.append("san_duplicate")
    if policy.get("require_lowercase_san") and any(s != s.lower() for s in san_dns):
        reasons.append("san_case")
    if not profile.get("allow_wildcard", False) and any("*" in s for s in san_dns):
        reasons.append("san_wildcard")
    suffixes = profile.get("san_suffixes") or []
    if profile and any(not _san_matches_suffix(s, suffixes) for s in san_dns):
        reasons.append("san_suffix")

    eku = obj.get("eku")
    if not isinstance(eku, list) or not all(isinstance(e, str) for e in eku):
        reasons.append("eku_type")
        eku = []
    if policy.get("require_unique_eku") and len(set(eku)) != len(eku):
        reasons.append("eku_duplicate")
    if profile:
        allowed = set(profile.get("eku_allowed") or [])
        required = set(profile.get("eku_required") or [])
        if not required.issubset(set(eku)):
            reasons.append("eku_required")
        if not set(eku).issubset(allowed):
            reasons.append("eku_allowed")

    der = obj.get("der_sha256")
    hex_len = policy.get("der_sha256_hex_len", 64)
    if not isinstance(der, str) or len(der) != hex_len or any(c not in "0123456789abcdefABCDEF" for c in der):
        reasons.append("der_sha256")
    elif policy.get("require_lowercase_hex") and der != der.lower():
        reasons.append("der_sha256_case")

    kid = obj.get("kid")
    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("key_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_type")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_stale")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_type")
    elif nonce in items:
        reasons.append("nonce_replay")

    if key_entry is not None and isinstance(obj.get("sig"), str):
        if not hmac.compare_digest(_expected_sig(key_entry.get("secret", ""), obj), obj["sig"]):
            reasons.append("bad_signature")
    else:
        reasons.append("bad_signature")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "profile": profile_name}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "profile": profile_name}
