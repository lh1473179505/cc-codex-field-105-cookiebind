from __future__ import annotations
import base64
import hashlib
import hmac

SIGNING_VERSION = "v1"
REQUIRED_FIELDS = ("kid", "module", "version", "hash", "algo", "nonce", "iat", "sig")

def inspect_sum(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "module": obj.get("module"),
        "version": obj.get("version"),
        "hash": obj.get("hash"),
        "algo": obj.get("algo"),
        "nonce": obj.get("nonce"),
    }


def _signing_line(obj: dict) -> str:
    return "|".join((
        SIGNING_VERSION,
        str(obj["kid"]),
        str(obj["module"]),
        str(obj["version"]),
        str(obj["hash"]),
        str(obj["algo"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def admit_sum(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    module = obj.get("module")

    malformed = any(obj.get(field) is None for field in REQUIRED_FIELDS)
    if malformed:
        reasons.append("missing_field")

    rule = policy.get("modules", {}).get(module) if isinstance(module, str) else None
    if rule is None:
        reasons.append("module_not_allowed")
    else:
        version = obj.get("version")
        prefixes = rule.get("version_prefixes", [])
        if not isinstance(version, str) or not any(version.startswith(prefix) for prefix in prefixes):
            reasons.append("version_prefix_denied")

        algo = obj.get("algo")
        if algo not in rule.get("algos", []):
            reasons.append("algo_not_allowed")
        if algo in policy.get("forbid_algos", []):
            reasons.append("algo_forbidden")

        digest = obj.get("hash")
        if not isinstance(digest, str) or len(digest) != rule.get("hash_len"):
            reasons.append("hash_len_mismatch")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")

    if not malformed and key is not None:
        try:
            key_bytes = bytes.fromhex(key.get("secret", ""))
        except (TypeError, ValueError):
            key_bytes = b""
            reasons.append("bad_sig")
        if key_bytes:
            mac = hmac.new(key_bytes, _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
            sig = obj.get("sig")
            if not isinstance(sig, str) or not hmac.compare_digest(_b64url(mac), sig):
                reasons.append("bad_sig")

    iat = obj.get("iat")
    if isinstance(iat, int) and not isinstance(iat, bool):
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_in_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")
    elif not malformed:
        reasons.append("iat_invalid")

    nonce = obj.get("nonce")
    if isinstance(nonce, str):
        items = store.setdefault("items", {})
        if nonce in items:
            reasons.append("nonce_replay")
    elif not malformed:
        reasons.append("nonce_invalid")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "module": module}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "module": module}
