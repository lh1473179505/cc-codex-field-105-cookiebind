from __future__ import annotations
import base64
import hashlib
import hmac

SCHEME = "v1"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _build_line(obj: dict) -> str | None:
    fields = (
        "kid",
        "sni",
        "version",
        "cipher",
        "alpn",
        "early_data",
        "max_early",
        "lifetime",
        "iat",
        "nonce",
    )
    values = []
    for name in fields:
        if name not in obj:
            return None
        values.append(obj[name])
    kid, sni, version, cipher, alpn, early_data, max_early, lifetime, iat, nonce = values

    if not isinstance(kid, str) or not isinstance(sni, str):
        return None
    if not isinstance(version, str) or not isinstance(cipher, str):
        return None
    if not isinstance(alpn, list) or not alpn or not all(isinstance(a, str) for a in alpn):
        return None
    if not isinstance(nonce, str) or not nonce:
        return None
    if isinstance(early_data, bool) or early_data not in (0, 1):
        return None
    for name, value in (
        ("max_early", max_early),
        ("lifetime", lifetime),
        ("iat", iat),
    ):
        if isinstance(value, bool) or not isinstance(value, int):
            return None

    return "|".join(
        (
            SCHEME,
            kid,
            sni,
            version,
            cipher,
            ",".join(alpn),
            str(early_data),
            str(max_early),
            str(lifetime),
            str(iat),
            nonce,
        )
    )


def inspect_ticket(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "sni": obj.get("sni"),
        "version": obj.get("version"),
        "cipher": obj.get("cipher"),
        "alpn": obj.get("alpn"),
        "early_data": obj.get("early_data"),
        "max_early": obj.get("max_early"),
        "lifetime": obj.get("lifetime"),
        "nonce": obj.get("nonce"),
    }


def admit_ticket(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    sni = obj.get("sni")
    reasons: list[str] = []

    def deny() -> dict:
        return {"decision": "deny", "reason_codes": reasons, "sni": sni}

    line = _build_line(obj)
    if line is None:
        reasons.append("malformed_ticket")
        return deny()

    hosts = policy.get("hosts", {})
    host = hosts.get(sni)
    if not isinstance(host, dict):
        reasons.append("sni_not_allowed")
        return deny()

    if obj["version"] not in host.get("versions", ()):
        reasons.append("version_not_allowed")
    if obj["cipher"] not in host.get("ciphers", ()):
        reasons.append("cipher_not_allowed")

    alpn = obj["alpn"]
    if policy.get("require_unique_alpn", True) and len(alpn) != len(set(alpn)):
        reasons.append("alpn_not_unique")
    for required in host.get("alpn_required", ()):
        if required not in alpn:
            reasons.append("alpn_required_missing")
            break
    allowed = host.get("alpn_allowed", ())
    if any(protocol not in allowed for protocol in alpn):
        reasons.append("alpn_not_allowed")

    early_data = obj["early_data"]
    max_early = obj["max_early"]
    early_supported = bool(host.get("early_allowed", False))
    limit = int(host.get("max_early_limit", 0))
    if early_data == 1:
        if obj["version"] != "TLS1.3":
            reasons.append("early_data_version_unsupported")
        if not early_supported:
            reasons.append("early_data_unsupported")
        if not (1 <= max_early <= limit):
            reasons.append("max_early_limit_exceeded")
    elif max_early != 0:
        reasons.append("early_data_coupling_invalid")
    if not early_supported and max_early != 0 and "early_data_unsupported" not in reasons:
        reasons.append("early_data_unsupported")

    lifetime = obj["lifetime"]
    if not (
        int(host.get("lifetime_min", 0))
        <= lifetime
        <= int(host.get("lifetime_max", 0))
    ):
        reasons.append("lifetime_out_of_range")

    key = keys.get("keys", {}).get(obj["kid"])
    if not isinstance(key, dict):
        reasons.append("unknown_kid")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        secret_hex = key.get("secret", "")
        try:
            secret = bytes.fromhex(secret_hex)
        except (TypeError, ValueError):
            secret = b""
        digest = hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url(digest), str(obj.get("sig", ""))):
            reasons.append("bad_signature")

    iat = obj["iat"]
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if iat > now_unix + skew:
        reasons.append("iat_in_future")
    if iat < now_unix - max_age:
        reasons.append("ticket_expired")

    items = store.setdefault("items", {})
    if obj["nonce"] in items:
        reasons.append("nonce_replayed")

    if reasons:
        return deny()

    items[obj["nonce"]] = {"ts": int(now_unix)}
    return {"decision": "allow", "reason_codes": [], "sni": sni}
