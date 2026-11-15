from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any
from urllib.parse import parse_qsl, urlencode

_HEX_DIGITS = frozenset("0123456789abcdef")


def inspect_challenge(ch: dict) -> dict:
    return {
        "kid": ch.get("kid"),
        "method": ch.get("method"),
        "host": ch.get("host"),
        "raw_path": ch.get("raw_path"),
        "query": ch.get("query"),
        "nonce": ch.get("nonce"),
    }


def admit_challenge(ch: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    """Admit an edge challenge ticket against keys, policy and the nonce store.

    Returns a report dict per docs/report-schema.md. On allow the nonce is
    written into ``store`` (in place); deny paths never mutate it.
    """
    reasons: list[str] = []

    kid = str(ch.get("kid", ""))
    method = str(ch.get("method", ""))
    host = str(ch.get("host", ""))
    raw_path = str(ch.get("raw_path", ""))
    query = ch.get("query", "")
    headers = ch.get("headers") or {}
    origin = str(ch.get("origin", ""))
    content_type = str(ch.get("content_type", ""))
    body_sha256 = str(ch.get("body_sha256", ""))
    nonce = str(ch.get("nonce", ""))
    sig = str(ch.get("sig", ""))

    # 1-2. Path safety first, then allow/deny prefixes on the raw string.
    lowered_path = raw_path.lower()
    if "%2e" in lowered_path or ".." in raw_path or "//" in raw_path or "\\" in raw_path:
        reasons.append("path_unsafe")
    else:
        denied = any(raw_path.startswith(p) for p in policy.get("path_deny_prefixes", []))
        allowed = any(raw_path.startswith(p) for p in policy.get("path_allow_prefixes", []))
        if denied or not allowed:
            reasons.append("path_denied")

    # Canonical query: parse keeping blanks, sort by (key, value), urlencode.
    if isinstance(query, str):
        pairs = parse_qsl(query, keep_blank_values=True)
    else:
        pairs = [(str(k), str(v)) for k, v in query]
    canon_query = urlencode(sorted(pairs))

    # Canonical headers: lowercase names, name=value, comma joined, sorted.
    lower_headers = {str(k).lower(): str(v) for k, v in headers.items()}
    headers_csv = ",".join(f"{name}={lower_headers[name]}" for name in sorted(lower_headers))

    # 3. HMAC + kid status.
    key_entry = keys.get("keys", {}).get(kid)
    if key_entry is None:
        reasons.append("unknown_kid")
    else:
        if key_entry.get("status") == "revoked":
            reasons.append("kid_revoked")
        signing_input = "|".join(
            [
                "v1",
                kid,
                method,
                host,
                raw_path,
                canon_query,
                headers_csv,
                origin,
                content_type,
                body_sha256,
                str(ch.get("iat", "")),
                str(ch.get("exp", "")),
                nonce,
            ]
        )
        expected_sig = _compute_signature(key_entry.get("secret", ""), signing_input)
        if not hmac.compare_digest(expected_sig, sig):
            reasons.append("bad_signature")

    # 4. host/method allowlists.
    if host not in policy.get("allowed_hosts", []):
        reasons.append("host_denied")
    if method not in policy.get("allowed_methods", []):
        reasons.append("method_denied")

    # 5. strict query keys.
    if policy.get("strict_query"):
        allowed_keys = set(policy.get("allowed_query_keys", []))
        if any(key not in allowed_keys for key, _ in pairs):
            reasons.append("query_key_denied")

    # 6. required headers present, denied headers absent (case-insensitive).
    if any(str(h).lower() not in lower_headers for h in policy.get("required_headers", [])):
        reasons.append("header_missing")
    if any(str(h).lower() in lower_headers for h in policy.get("denied_headers", [])):
        reasons.append("header_denied")

    # 7. credentials mode: origin exact whitelist.
    if policy.get("credentials_mode") and policy.get("require_origin_for_credentials"):
        if origin not in policy.get("allowed_origins", []):
            reasons.append("origin_denied")

    # 8. POST body gates.
    if method in policy.get("require_body_hash_for", []):
        if content_type not in policy.get("allowed_content_types", []):
            reasons.append("content_type_denied")
        if not (len(body_sha256) == 64 and all(c in _HEX_DIGITS for c in body_sha256.lower())):
            reasons.append("body_hash_invalid")

    # 9. time window + nonce store (write only on allow).
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    try:
        iat = int(ch.get("iat"))
        exp = int(ch.get("exp"))
        now = int(now_unix)
    except (TypeError, ValueError):
        iat = exp = now = None  # type: ignore[assignment]
    if now is None:
        reasons.append("timestamp_skew")
    else:
        if iat - now > skew:
            reasons.append("timestamp_skew")
        if now - exp > skew:
            reasons.append("token_expired")
        if max_age > 0 and now - iat > max_age:
            reasons.append("token_too_old")

    items = store.get("items") if isinstance(store, dict) else None
    if items is None:
        items = {}
    if nonce in items:
        reasons.append("replay")

    decision = "allow" if not reasons else "deny"
    if decision == "allow":
        store.setdefault("items", {})[nonce] = {"ts": int(now_unix)}

    return {"decision": decision, "reason_codes": reasons, "path": raw_path}


def _compute_signature(secret: str, signing_input: str) -> str:
    digest = hmac.new(
        _decode_secret(secret), signing_input.encode("ascii"), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _decode_secret(secret: str) -> bytes:
    raw = secret.encode("utf-8")
    if len(secret) % 2 == 0:
        try:
            return bytes.fromhex(secret)
        except ValueError:
            pass
    return raw
