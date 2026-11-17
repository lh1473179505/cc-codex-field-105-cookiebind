from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_rule(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "zone": obj.get("zone"),
        "owner": obj.get("owner"),
        "qname": obj.get("qname"),
        "action": obj.get("action"),
        "cname_target": obj.get("cname_target"),
        "ttl": obj.get("ttl"),
        "rule_sha256": obj.get("rule_sha256"),
        "nonce": obj.get("nonce"),
    }

def _sig_line(obj: dict) -> str:
    return "v1|{kid}|{zone}|{owner}|{qname}|{action}|{cname_target}|{ttl}|{rule_sha256}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        zone=obj.get("zone"),
        owner=obj.get("owner"),
        qname=obj.get("qname"),
        action=obj.get("action"),
        cname_target=obj.get("cname_target"),
        ttl=obj.get("ttl"),
        rule_sha256=obj.get("rule_sha256"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _is_lower_hex(s: str) -> bool:
    return all(c in "0123456789abcdef" for c in s)

def _under_suffix(name: str, suffix: str) -> bool:
    return name == suffix or name.endswith("." + suffix)

def admit_rule(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    owner = obj.get("owner")

    zone = obj.get("zone")
    zones = policy.get("zones", {})
    zcfg = zones.get(zone)
    if zcfg is None:
        reasons.append("zone_not_configured")
        zcfg = {}

    qname = obj.get("qname")
    if not isinstance(qname, str) or not qname or qname != qname.lower() or qname.endswith("."):
        reasons.append("qname_shape")
        qname_ok = False
    else:
        qname_ok = True
    if qname_ok:
        body = qname
        if body.startswith("*."):
            if not policy.get("allow_leading_wildcard", False):
                reasons.append("wildcard_not_allowed")
            body = body[2:]
        if "*" in body:
            reasons.append("wildcard_shape")
        suffixes = zcfg.get("qname_suffixes", [])
        if not any(_under_suffix(qname, s) for s in suffixes):
            reasons.append("qname_suffix")

    if owner != f"{qname}.{zone}":
        reasons.append("owner_binding")

    action = obj.get("action")
    if action not in zcfg.get("actions", []):
        reasons.append("action_not_allowed")

    cname_target = obj.get("cname_target")
    if action == "CNAME":
        if not isinstance(cname_target, str) or not cname_target:
            reasons.append("cname_missing")
        elif cname_target != cname_target.lower() or not cname_target.endswith("."):
            reasons.append("cname_shape")
        elif not any(_under_suffix(cname_target, s) for s in zcfg.get("cname_suffixes", [])):
            reasons.append("cname_suffix")
    else:
        if cname_target != "":
            reasons.append("cname_unexpected")

    ttl = obj.get("ttl")
    if not isinstance(ttl, int) or isinstance(ttl, bool):
        reasons.append("ttl_shape")
    elif zcfg:
        if ttl < zcfg.get("ttl_min", 0) or ttl > zcfg.get("ttl_max", 0):
            reasons.append("ttl_range")

    digest = obj.get("rule_sha256")
    want_len = policy.get("rule_sha256_hex_len", 64)
    if not isinstance(digest, str) or len(digest) != want_len or (
        policy.get("require_lowercase_hex", True) and not _is_lower_hex(digest)
    ):
        reasons.append("rule_sha256_format")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid)
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        secret = bytes.fromhex(key.get("secret", ""))
        expect = hmac.new(secret, _sig_line(obj).encode("utf-8"), hashlib.sha256).digest()
        sig = obj.get("sig")
        try:
            got = _b64url_decode(sig) if isinstance(sig, str) else b""
        except Exception:
            got = b""
        if not hmac.compare_digest(expect, got):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_shape")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if iat < now_unix - policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        reasons.append("replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "owner": owner}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "owner": owner}
