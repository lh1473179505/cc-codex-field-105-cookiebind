from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_pub(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "project": obj.get("project"),
        "issuer": obj.get("issuer"),
        "sub": obj.get("sub"),
        "claim": obj.get("claim"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{project}|{issuer}|{sub}|{claim}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        project=obj.get("project"),
        issuer=obj.get("issuer"),
        sub=obj.get("sub"),
        claim=obj.get("claim"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_pub(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    project = obj.get("project")

    proj = (policy.get("projects") or {}).get(project)
    if proj is None:
        reasons.append("unknown_project")
    else:
        if obj.get("issuer") not in (proj.get("issuers") or []):
            reasons.append("issuer_mismatch")
        sub = obj.get("sub")
        if not isinstance(sub, str) or not any(sub.startswith(p) for p in (proj.get("subs") or [])):
            reasons.append("sub_mismatch")
        if obj.get("claim") not in (proj.get("claims") or []):
            reasons.append("claim_mismatch")

    key = (keys.get("keys") or {}).get(obj.get("kid"))
    if key is None:
        reasons.append("unknown_key")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        expected = _expected_sig(key.get("secret", ""), _signing_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("bad_iat")
    elif iat > now_unix + skew or iat < now_unix - max_age:
        reasons.append("iat_out_of_window")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if not isinstance(nonce, str) or not nonce:
        reasons.append("bad_nonce")
    elif nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "project": project}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "project": project}
