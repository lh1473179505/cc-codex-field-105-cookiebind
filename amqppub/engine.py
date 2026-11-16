from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_message(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "vhost": obj.get("vhost"),
        "exchange": obj.get("exchange"),
        "routing_key": obj.get("routing_key"),
        "delivery_mode": obj.get("delivery_mode"),
        "headers": obj.get("headers"),
        "body_sha256": obj.get("body_sha256"),
        "nonce": obj.get("nonce"),
    }

def _signature_line(obj: dict) -> str:
    headers = obj.get("headers") or {}
    header_field = ",".join(f"{k}={headers[k]}" for k in sorted(headers))
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("user")),
        str(obj.get("vhost")),
        str(obj.get("exchange")),
        str(obj.get("routing_key")),
        str(obj.get("delivery_mode")),
        header_field,
        str(obj.get("body_sha256")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _is_lower_hex_64(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )

def admit_message(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []
    routing_key = obj.get("routing_key") if isinstance(obj, dict) else None

    if not isinstance(obj, dict):
        return {"decision": "deny", "reason_codes": ["message_shape"], "routing_key": None}

    headers = obj.get("headers")
    if not isinstance(headers, dict):
        codes.append("headers_shape")
        headers = {}

    # vhost -> user -> exchange binding
    vhosts = policy.get("vhosts") or {}
    vhost = vhosts.get(obj.get("vhost"))
    exchange = None
    if vhost is None:
        codes.append("vhost_unknown")
    else:
        user = (vhost.get("users") or {}).get(obj.get("user"))
        if user is None:
            codes.append("user_not_bound")
        else:
            exchange = (user.get("exchanges") or {}).get(obj.get("exchange"))
            if exchange is None:
                codes.append("exchange_not_bound")

    # routing key and delivery mode
    if exchange is not None:
        if not isinstance(routing_key, str) or not any(
            routing_key.startswith(p) for p in exchange.get("routing_prefixes") or []
        ):
            codes.append("routing_prefix")
        if policy.get("forbid_wildcard_routing") and isinstance(routing_key, str) and (
            "*" in routing_key or "#" in routing_key
        ):
            codes.append("routing_wildcard")
        if obj.get("delivery_mode") not in (exchange.get("delivery_modes") or []):
            codes.append("delivery_mode")

        # headers: allowed subset, required exact values, deny set
        allowed = set(exchange.get("allowed_headers") or [])
        for name in headers:
            if name not in allowed:
                codes.append("header_not_allowed")
                break
        for name, value in (exchange.get("required_headers") or {}).items():
            if name not in headers:
                codes.append("header_required")
            elif headers[name] != value:
                codes.append("header_value")
        for name in exchange.get("deny_headers") or []:
            if name in headers:
                codes.append("header_denied")
                break

    # body digest shape
    if not _is_lower_hex_64(obj.get("body_sha256")):
        codes.append("body_sha256")

    # key status
    key = (keys.get("keys") or {}).get(obj.get("kid"))
    if key is None:
        codes.append("kid_unknown")
    elif key.get("status") != "active":
        codes.append("key_revoked")

    # time window
    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        codes.append("iat_shape")
    else:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat > now_unix + skew or iat < now_unix - max_age:
            codes.append("iat_out_of_window")

    # replay
    nonce = obj.get("nonce")
    items = store.get("items") or {}
    if not isinstance(nonce, str) or not nonce:
        codes.append("nonce_shape")
    elif nonce in items:
        codes.append("nonce_replay")

    # signature (sorted headers enter the HMAC line)
    if key is not None and isinstance(key.get("secret"), str):
        expected = base64.urlsafe_b64encode(
            hmac.new(
                bytes.fromhex(key["secret"]),
                _signature_line(obj).encode("utf-8"),
                hashlib.sha256,
            ).digest()
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            codes.append("bad_signature")
    else:
        codes.append("bad_signature")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "routing_key": routing_key}

    items[nonce] = {"ts": now_unix}
    store["items"] = items
    return {"decision": "allow", "reason_codes": [], "routing_key": routing_key}
