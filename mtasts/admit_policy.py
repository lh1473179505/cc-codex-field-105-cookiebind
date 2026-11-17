from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any


def inspect_policy(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "policy_id": obj.get("policy_id"),
        "domain": obj.get("domain"),
        "mode": obj.get("mode"),
        "mx": obj.get("mx"),
        "max_age": obj.get("max_age"),
        "report_domain": obj.get("report_domain"),
        "policy_sha256": obj.get("policy_sha256"),
        "nonce": obj.get("nonce"),
    }


def _deny(obj: dict, reason_codes: list[str]) -> dict:
    return {
        "decision": "deny",
        "reason_codes": reason_codes,
        "domain": obj.get("domain"),
    }


def _mx_allowed(host: str, suffixes: list[str]) -> bool:
    for suffix in suffixes:
        if host == suffix:
            return True
        if host.endswith("." + suffix):
            prefix = host[: -(len(suffix) + 1)]
            if prefix and "." not in prefix:
                return True
    return False


def _signing_input(obj: dict) -> str:
    return "v1|" + "|".join(
        [
            str(obj["kid"]),
            str(obj["policy_id"]),
            str(obj["domain"]),
            str(obj["mode"]),
            ",".join(str(host) for host in obj["mx"]),
            str(obj["max_age"]),
            str(obj["report_domain"]),
            str(obj["policy_sha256"]),
            str(obj["iat"]),
            str(obj["nonce"]),
        ]
    )


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def admit_policy(
    obj: dict,
    keys: dict,
    policy: dict,
    store: dict,
    now_unix: int,
) -> dict:
    reasons: list[str] = []

    domain = obj.get("domain")
    domains = policy.get("domains", {})
    if not isinstance(domain, str) or domain not in domains:
        return _deny(obj, ["unknown_domain"])
    cfg = domains[domain]

    if obj.get("policy_id") not in cfg.get("policy_ids", []):
        reasons.append("policy_id_not_allowed")

    if obj.get("mode") not in cfg.get("modes", []):
        reasons.append("mode_not_allowed")

    if obj.get("report_domain") not in cfg.get("report_domains", []):
        reasons.append("report_domain_misaligned")

    digest = obj.get("policy_sha256")
    hex_len = policy.get("policy_sha256_hex_len", 64)
    if (
        not isinstance(digest, str)
        or len(digest) != hex_len
        or any(ch not in "0123456789abcdef" for ch in digest)
    ):
        reasons.append("policy_sha256_bad_format")

    mx = obj.get("mx")
    if not isinstance(mx, list):
        reasons.append("mx_shape_invalid")
        mx = []

    if not (policy.get("mx_min", 1) <= len(mx) <= policy.get("mx_max", 3)):
        reasons.append("mx_count_out_of_range")

    if policy.get("require_unique_mx", True) and len(mx) != len(set(mx)):
        reasons.append("mx_not_unique")

    suffixes = cfg.get("mx_suffixes", [])
    require_lowercase = policy.get("require_lowercase_names", True)
    for host in mx:
        if not isinstance(host, str) or not host:
            reasons.append("mx_host_invalid")
            continue
        if require_lowercase and host != host.lower():
            reasons.append("mx_host_not_lowercase")
        if not _mx_allowed(host, suffixes):
            reasons.append("mx_suffix_violation")

    for required in cfg.get("mx_required", []):
        if required not in mx:
            reasons.append("mx_required_missing")

    max_age = obj.get("max_age")
    if (
        not isinstance(max_age, int)
        or isinstance(max_age, bool)
        or not (cfg.get("max_age_min", 0) <= max_age <= cfg.get("max_age_max", 0))
    ):
        reasons.append("max_age_out_of_range")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if not isinstance(key_entry, dict):
        reasons.append("unknown_kid")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    signature_ok = False
    if isinstance(key_entry, dict):
        try:
            secret = bytes.fromhex(key_entry["secret"])
            expected = hmac.new(
                secret,
                _signing_input(obj).encode("utf-8"),
                hashlib.sha256,
            ).digest()
            signature_ok = hmac.compare_digest(
                _b64url(expected), str(obj.get("sig", ""))
            )
        except (ValueError, TypeError, KeyError):
            signature_ok = False
    if not signature_ok:
        reasons.append("bad_signature")

    iat = obj.get("iat")
    skew = policy.get("clock_skew_seconds", 60)
    window = policy.get("max_age_seconds", 600)
    if not isinstance(iat, int) or isinstance(iat, bool) or not (
        now_unix - window <= iat <= now_unix + skew
    ):
        reasons.append("iat_outside_window")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return _deny(obj, reasons)

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {
        "decision": "allow",
        "reason_codes": [],
        "domain": domain,
    }
