from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any
from urllib.parse import urlsplit

def inspect_delivery(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "url": obj.get("url"),
        "host": obj.get("host"),
        "method": obj.get("method"),
        "body_sha256": obj.get("body_sha256"),
        "event": obj.get("event"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    fields = ("kid", "url", "host", "method", "body_sha256", "event", "iat", "nonce")
    return "v1|" + "|".join(str(obj.get(f)) for f in fields)

def _expected_sig(secret_hex: str, line: str) -> str:
    mac = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")

def _is_hex(s: str) -> bool:
    return all(c in "0123456789abcdefABCDEF" for c in s)

def admit_delivery(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []

    url = obj.get("url")
    host = obj.get("host")
    parsed = None
    if isinstance(url, str):
        try:
            parsed = urlsplit(url)
        except ValueError:
            codes.append("url_parse_error")
    else:
        codes.append("url_missing")

    if parsed is not None:
        if parsed.scheme not in policy.get("allowed_schemes", []):
            codes.append("scheme_not_allowed")
        hostname = parsed.hostname
        if not hostname or hostname != host:
            codes.append("host_mismatch")
        elif hostname not in policy.get("allowed_hosts", []):
            codes.append("host_not_allowed")
        if policy.get("forbid_userinfo") and (parsed.username is not None or parsed.password is not None):
            codes.append("userinfo_forbidden")
        if policy.get("forbid_query") and parsed.query:
            codes.append("query_forbidden")
        if policy.get("forbid_fragment") and parsed.fragment:
            codes.append("fragment_forbidden")
        path = parsed.path or ""
        if ".." in path or "//" in path:
            codes.append("path_traversal")
        elif not any(path.startswith(p) for p in policy.get("path_allow_prefixes", [])):
            codes.append("path_not_allowed")

    if obj.get("method") not in policy.get("allowed_methods", []):
        codes.append("method_not_allowed")
    if obj.get("event") not in policy.get("allowed_events", []):
        codes.append("event_not_allowed")

    body_sha256 = obj.get("body_sha256")
    want_len = int(policy.get("body_sha256_hex_len", 64))
    if not isinstance(body_sha256, str) or len(body_sha256) != want_len or not _is_hex(body_sha256):
        codes.append("bad_body_sha256")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        codes.append("bad_iat")
    else:
        if now_unix - iat > int(policy.get("max_age_seconds", 0)):
            codes.append("iat_expired")
        if iat - now_unix > int(policy.get("clock_skew_seconds", 0)):
            codes.append("iat_in_future")

    nonce = obj.get("nonce")
    items = store.get("items", {})
    if not isinstance(nonce, str) or not nonce:
        codes.append("bad_nonce")
    elif nonce in items:
        codes.append("nonce_replay")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid)
    if key is None:
        codes.append("unknown_kid")
    elif key.get("status") != "active":
        codes.append("key_revoked")
    else:
        expected = _expected_sig(key["secret"], _signing_line(obj))
        sig = obj.get("sig")
        if not isinstance(sig, str) or not hmac.compare_digest(expected, sig):
            codes.append("bad_signature")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "event": obj.get("event")}

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "event": obj.get("event")}
