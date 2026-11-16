from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_srv(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "server": obj.get("server"),
        "client": obj.get("client"),
        "port": obj.get("port"),
        "meshtls": obj.get("meshtls"),
        "nonce": obj.get("nonce"),
    }

def admit_srv(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    server = obj.get("server")
    reasons: list[str] = []

    required = ("kid", "server", "client", "port", "meshtls", "iat", "nonce", "sig")
    if any(obj.get(field) is None for field in required):
        return {"decision": "deny", "reason_codes": ["malformed_request"], "server": server}

    servers = policy.get("servers", {})
    srv_policy = servers.get(server)
    if srv_policy is None:
        reasons.append("unknown_server")
    else:
        if obj["client"] not in srv_policy.get("clients", []):
            reasons.append("client_not_allowed")
        if obj["port"] not in srv_policy.get("ports", []):
            reasons.append("port_not_allowed")
        if srv_policy.get("require_meshtls") and obj["meshtls"] != 1:
            reasons.append("meshtls_required")

    key = keys.get("keys", {}).get(obj["kid"])
    if key is None:
        reasons.append("unknown_kid")
    else:
        if key.get("status") != "active":
            reasons.append("key_revoked")
        message = "v1|{}|{}|{}|{}|{}|{}|{}".format(
            obj["kid"], obj["server"], obj["client"], obj["port"],
            obj["meshtls"], obj["iat"], obj["nonce"],
        )
        expected = hmac.new(
            bytes.fromhex(key["secret"]), message.encode("utf-8"), hashlib.sha256
        ).digest()
        provided = obj["sig"]
        if not isinstance(provided, str):
            reasons.append("bad_signature")
        else:
            try:
                provided_bytes = base64.urlsafe_b64decode(provided + "=" * (-len(provided) % 4))
            except Exception:
                provided_bytes = b""
            if not hmac.compare_digest(expected, provided_bytes):
                reasons.append("bad_signature")

    iat = obj["iat"]
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("bad_iat")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("token_not_yet_valid")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("token_expired")

    items = store.setdefault("items", {})
    if obj["nonce"] in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "server": server}

    items[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "server": server}
