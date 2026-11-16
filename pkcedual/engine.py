from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any
from urllib.parse import urlsplit

def inspect_exch(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "client_id": obj.get("client_id"),
        "code": obj.get("code"),
        "challenge": obj.get("challenge"),
        "method": obj.get("method"),
        "redirect": obj.get("redirect"),
        "jkt": obj.get("jkt"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{client_id}|{code}|{challenge}|{method}|{redirect}|{jkt}|{auth_method}|{iat}|{nonce}".format(
        kid=obj.get("kid", ""),
        client_id=obj.get("client_id", ""),
        code=obj.get("code", ""),
        challenge=obj.get("challenge", ""),
        method=obj.get("method", ""),
        redirect=obj.get("redirect", ""),
        jkt=obj.get("jkt", ""),
        auth_method=obj.get("auth_method", ""),
        iat=obj.get("iat", ""),
        nonce=obj.get("nonce", ""),
    )

def _b64url_hmac(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _redirect_ok(redirect: str, client: dict, policy: dict) -> bool:
    if not isinstance(redirect, str) or not redirect:
        return False
    parts = urlsplit(redirect)
    if policy.get("redirect_forbid_userinfo") and (parts.username is not None or parts.password is not None):
        return False
    if policy.get("redirect_forbid_query") and parts.query:
        return False
    if policy.get("redirect_forbid_fragment") and parts.fragment:
        return False
    allowed = client.get("redirects", [])
    if redirect in allowed:
        return True
    if policy.get("redirect_normalize_strip_slash"):
        stripped = redirect.rstrip("/")
        return any(stripped == a.rstrip("/") for a in allowed)
    return False

def admit_exch(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    client_id = obj.get("client_id")
    clients = policy.get("clients", {})
    client = clients.get(client_id)
    if client is None:
        return {"decision": "deny", "reason_codes": ["client_unknown"], "client_id": client_id}

    if not _redirect_ok(obj.get("redirect"), client, policy):
        reasons.append("redirect_not_allowed")

    method = obj.get("method")
    if method not in client.get("methods", []):
        reasons.append("method_not_allowed")
    if policy.get("forbid_plain") and method == "plain":
        reasons.append("plain_forbidden")
    challenge = obj.get("challenge")
    if not isinstance(challenge, str) or len(challenge) != client.get("challenge_len"):
        reasons.append("challenge_len")

    code = obj.get("code")
    prefixes = client.get("code_prefix", [])
    if not isinstance(code, str) or not any(code.startswith(p) for p in prefixes):
        reasons.append("code_prefix")

    jkt = obj.get("jkt")
    if client.get("require_jkt"):
        if not jkt:
            reasons.append("jkt_required")
        elif jkt not in client.get("jkts", []):
            reasons.append("jkt_not_allowed")

    if obj.get("auth_method") not in client.get("auth_methods", []):
        reasons.append("auth_method_not_allowed")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid)
    if key is None:
        reasons.append("kid_unknown")
    elif key.get("status") == "revoked":
        reasons.append("kid_revoked")
    else:
        expected = _b64url_hmac(key.get("secret", ""), _signing_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig", ""))):
            reasons.append("bad_sig")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")

    items = store.get("items", {})
    nonce = obj.get("nonce")
    if nonce in items:
        reasons.append("nonce_replay")
    if policy.get("code_reuse_is_deny") and code in items:
        reasons.append("code_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "client_id": client_id}

    items[nonce] = {"ts": now_unix}
    items[code] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "client_id": client_id}
