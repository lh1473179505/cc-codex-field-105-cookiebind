from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_image(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "ref": obj.get("ref"),
        "digest": obj.get("digest"),
        "platform": obj.get("platform"),
        "cap_drop": obj.get("cap_drop"),
        "seccomp": obj.get("seccomp"),
        "nonce": obj.get("nonce"),
    }

def _sign_line(obj: dict) -> str:
    caps = obj.get("cap_drop") or []
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("ref")),
        str(obj.get("digest")),
        str(obj.get("platform")),
        ",".join(str(c) for c in caps),
        str(obj.get("seccomp")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _valid_digest(digest: Any, prefix: str) -> bool:
    if not isinstance(digest, str) or not digest.startswith(prefix):
        return False
    hexpart = digest[len(prefix):]
    if len(hexpart) != 64:
        return False
    return all(c in "0123456789abcdef" for c in hexpart)

def admit_image(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    ref = obj.get("ref")
    digest = obj.get("digest")
    platform = obj.get("platform")
    cap_drop = obj.get("cap_drop") or []
    seccomp = obj.get("seccomp")
    nonce = obj.get("nonce")
    iat = obj.get("iat")
    kid = obj.get("kid")

    # repo prefix + digest pin
    allowed_repos = policy.get("allowed_repos") or []
    if not isinstance(ref, str) or not any(ref.startswith(r) for r in allowed_repos):
        reasons.append("repo_not_allowed")
    prefix = policy.get("digest_prefix", "sha256:")
    if policy.get("forbid_mutable_tag_only"):
        if not isinstance(ref, str) or "@" not in ref:
            reasons.append("mutable_tag_ref")
        elif ref.split("@", 1)[1] != digest:
            reasons.append("digest_mismatch")
    if not _valid_digest(digest, prefix):
        reasons.append("digest_invalid")

    # platform / caps / seccomp
    if platform not in (policy.get("allowed_platforms") or []):
        reasons.append("platform_not_allowed")
    cap_set = set(cap_drop)
    if not set(policy.get("required_cap_drop") or []).issubset(cap_set):
        reasons.append("cap_drop_missing")
    if cap_set & set(policy.get("forbidden_caps") or []):
        reasons.append("cap_forbidden")
    if seccomp not in (policy.get("allowed_seccomp") or []):
        reasons.append("seccomp_not_allowed")

    # key status + HMAC
    key = (keys.get("keys") or {}).get(kid)
    if key is None:
        reasons.append("key_unknown")
    else:
        if key.get("status") != "active":
            reasons.append("key_revoked")
        else:
            secret = bytes.fromhex(key["secret"])
            expect = base64.urlsafe_b64encode(
                hmac.new(secret, _sign_line(obj).encode("utf-8"), hashlib.sha256).digest()
            ).decode("ascii").rstrip("=")
            if not hmac.compare_digest(expect, str(obj.get("sig"))):
                reasons.append("bad_sig")

    # time window
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + skew:
            reasons.append("iat_future")
        if now_unix - iat > max_age:
            reasons.append("iat_stale")

    # nonce allow-only (replay protection)
    items = store.setdefault("items", {})
    if not nonce or nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "ref": ref}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "ref": ref}
