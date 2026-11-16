from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_request(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "profile": obj.get("profile"),
        "cn": obj.get("cn"),
        "dns_names": obj.get("dns_names"),
        "key_alg": obj.get("key_alg"),
        "key_bits": obj.get("key_bits"),
        "key_usage": obj.get("key_usage"),
        "challenge": obj.get("challenge"),
        "nonce": obj.get("nonce"),
    }

def _signed_line(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("profile")),
        str(obj.get("cn")),
        ",".join(obj.get("dns_names") or []),
        str(obj.get("key_alg")),
        str(obj.get("key_bits")),
        ",".join(obj.get("key_usage") or []),
        str(obj.get("challenge")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _valid_name(name: Any, suffixes: list) -> bool:
    if not isinstance(name, str) or name != name.lower():
        return False
    for suffix in suffixes:
        if name.endswith(suffix):
            head = name[: -len(suffix)]
            if head and "." not in head:
                return True
    return False

def admit_request(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []
    profiles = policy.get("profiles") or {}
    profile = profiles.get(obj.get("profile"))
    if profile is None:
        codes.append("profile_unknown")
    else:
        if not _valid_name(obj.get("cn"), profile.get("cn_suffixes") or []):
            codes.append("cn_suffix")
        dns_names = obj.get("dns_names")
        if not isinstance(dns_names, list) or not all(isinstance(n, str) for n in dns_names):
            codes.append("dns_suffix")
            dns_names = []
        else:
            if any(not _valid_name(n, profile.get("dns_suffixes") or []) for n in dns_names):
                codes.append("dns_suffix")
            if policy.get("require_unique_dns") and len(set(dns_names)) != len(dns_names):
                codes.append("dns_not_unique")
            max_dns = policy.get("max_dns_names")
            if max_dns is not None and len(dns_names) > max_dns:
                codes.append("dns_too_many")
        if policy.get("require_cn_in_dns") and obj.get("cn") not in dns_names:
            codes.append("cn_not_in_dns")
        if obj.get("key_alg") not in (profile.get("key_algs") or []):
            codes.append("key_alg")
        if obj.get("key_bits") not in (profile.get("key_bits") or []):
            codes.append("key_bits")
        usage = obj.get("key_usage")
        if not isinstance(usage, list) or not all(isinstance(u, str) for u in usage):
            codes.append("key_usage")
        else:
            usage_set = set(usage)
            if not set(profile.get("required_usage") or []) <= usage_set:
                codes.append("key_usage_missing")
            if not usage_set <= set(profile.get("allowed_usage") or []):
                codes.append("key_usage_extra")
        challenge = obj.get("challenge")
        prefixes = profile.get("challenge_prefixes") or []
        min_len = profile.get("challenge_min_len") or 0
        if (
            not isinstance(challenge, str)
            or not any(challenge.startswith(p) for p in prefixes)
            or len(challenge) < min_len - 1
        ):
            codes.append("challenge")
    key = (keys.get("keys") or {}).get(obj.get("kid"))
    if key is None:
        codes.append("kid_unknown")
    else:
        if key.get("status") != "active":
            codes.append("key_revoked")
        secret = bytes.fromhex(key.get("secret", ""))
        expected = base64.urlsafe_b64encode(
            hmac.new(secret, _signed_line(obj).encode("utf-8"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            codes.append("sig_invalid")
    iat = obj.get("iat")
    if not isinstance(iat, int):
        codes.append("iat_invalid")
    else:
        skew = policy.get("clock_skew_seconds") or 0
        max_age = policy.get("max_age_seconds")
        if iat > now_unix + skew or (max_age is not None and now_unix - iat > max_age):
            codes.append("iat_out_of_window")
    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        codes.append("nonce_invalid")
    elif nonce in (store.get("items") or {}):
        codes.append("nonce_replay")
    if codes:
        return {"decision": "deny", "reason_codes": codes, "cn": obj.get("cn")}
    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "cn": obj.get("cn")}
