from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_chain(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "leaf": obj.get("leaf"),
        "chain": obj.get("chain"),
        "eku": obj.get("eku"),
        "dns": obj.get("dns"),
        "nonce": obj.get("nonce"),
    }

def _b64url_no_pad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _signing_input(obj: dict) -> str:
    return "v1|{kid}|{leaf}|{chain}|{eku}|{dns}|{iat}|{exp}|{nonce}".format(
        kid=obj.get("kid"),
        leaf=obj.get("leaf"),
        chain=",".join(obj.get("chain") or []),
        eku=obj.get("eku"),
        dns=obj.get("dns"),
        iat=obj.get("iat"),
        exp=obj.get("exp"),
        nonce=obj.get("nonce"),
    )

def admit_chain(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    leaf = obj.get("leaf")
    chain = obj.get("chain")

    if not isinstance(chain, list) or not all(isinstance(c, str) for c in chain):
        reasons.append("chain_malformed")
        chain = []

    min_len = policy.get("min_chain_len", 1)
    max_len = policy.get("max_chain_len", len(chain))
    if not (min_len <= len(chain) <= max_len):
        reasons.append("chain_len")

    if chain:
        if policy.get("require_chain_leaf_first", False) and chain[0] != leaf:
            reasons.append("leaf_mismatch")
        if chain[-1] not in policy.get("trusted_roots", []):
            reasons.append("untrusted_root")
        if policy.get("forbid_duplicate_certs", False) and len(set(chain)) != len(chain):
            reasons.append("duplicate_cert")

    if obj.get("eku") not in policy.get("allowed_eku", []):
        reasons.append("eku_not_allowed")

    dns = obj.get("dns")
    if not isinstance(dns, str) or not any(
        dns.endswith(suffix) for suffix in policy.get("allowed_dns_suffixes", [])
    ):
        reasons.append("dns_not_allowed")

    iat = obj.get("iat")
    exp = obj.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int):
        reasons.append("time_malformed")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        if iat > now_unix + skew:
            reasons.append("not_yet_valid")
        if now_unix > exp:
            reasons.append("expired")
        if exp - iat > policy.get("max_age_seconds", exp - iat):
            reasons.append("age_exceeded")

    kid = obj.get("kid")
    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("unknown_kid")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        try:
            secret = bytes.fromhex(key_entry.get("secret", ""))
        except ValueError:
            secret = b""
        expected = _b64url_no_pad(hmac.new(secret, _signing_input(obj).encode("utf-8"), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_sig")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_malformed")
    elif nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "leaf": leaf}

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "leaf": leaf}
