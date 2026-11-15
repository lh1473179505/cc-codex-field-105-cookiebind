from __future__ import annotations
import base64
import hashlib
import hmac
import json
from typing import Any


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _secret_bytes(entry: dict) -> bytes | None:
    secret = entry.get("secret")
    if not isinstance(secret, str):
        return None
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def _decode_jws(compact: str):
    parts = compact.split(".")
    if len(parts) != 3:
        return None
    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(signature_b64)
    except ValueError:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    signing_input = (header_b64 + "." + payload_b64).encode("ascii")
    return header, payload, signing_input, signature


def _hs256_verify(key: bytes, signing_input: bytes, signature: bytes) -> bool:
    expected = hmac.new(key, signing_input, hashlib.sha256).digest()
    return hmac.compare_digest(expected, signature)


def inspect_token(token: dict) -> dict:
    return {"has_outer": bool(token.get("outer")), "nonce": token.get("nonce")}

def admit_token(token: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    report_sub = ""
    report_aud = ""

    def deny(code: str) -> dict:
        return {
            "decision": "deny",
            "reason_codes": [code],
            "sub": report_sub,
            "aud": report_aud,
        }

    compact = token.get("outer")
    if not isinstance(compact, str):
        return deny("outer_malformed")

    # 1. Split outer; verify HS256 with outer kid; typ allowed; kid not revoked.
    outer = _decode_jws(compact)
    if outer is None:
        return deny("outer_malformed")
    outer_header, outer_payload, outer_signing_input, outer_signature = outer

    if outer_header.get("alg") != "HS256":
        return deny("outer_alg_unsupported")
    outer_kid = outer_header.get("kid")
    outer_entry = keys.get("outer_keys", {}).get(outer_kid)
    if outer_entry is None:
        return deny("outer_kid_unknown")
    outer_key = _secret_bytes(outer_entry)
    if outer_key is None:
        return deny("outer_kid_unknown")
    if not _hs256_verify(outer_key, outer_signing_input, outer_signature):
        return deny("outer_bad_signature")
    if outer_header.get("typ") not in policy.get("allowed_outer_typ", []):
        return deny("outer_typ_denied")
    if outer_entry.get("status") != "active":
        return deny("outer_kid_revoked")

    # 2. Take the nested jwt string raw from the outer payload.
    nested = outer_payload.get("jwt")
    if not isinstance(nested, str):
        return deny("inner_missing")

    # 3. Verify inner HS256 with inner kid; typ allowed; kid not revoked.
    inner = _decode_jws(nested)
    if inner is None:
        return deny("inner_malformed")
    inner_header, inner_payload, inner_signing_input, inner_signature = inner

    sub = inner_payload.get("sub")
    aud = inner_payload.get("aud")
    report_sub = sub if isinstance(sub, str) else ""
    report_aud = aud if isinstance(aud, str) else ""

    if inner_header.get("alg") != "HS256":
        return deny("inner_alg_unsupported")
    inner_kid = inner_header.get("kid")
    inner_entry = keys.get("inner_keys", {}).get(inner_kid)
    if inner_entry is None:
        return deny("inner_kid_unknown")
    inner_key = _secret_bytes(inner_entry)
    if inner_key is None:
        return deny("inner_kid_unknown")
    if not _hs256_verify(inner_key, inner_signing_input, inner_signature):
        return deny("inner_bad_signature")
    if inner_header.get("typ") not in policy.get("allowed_inner_typ", []):
        return deny("inner_typ_denied")
    if inner_entry.get("status") != "active":
        return deny("inner_kid_revoked")

    # 4. cnf.jkt binds the thumbprint of the inner signing key.
    if policy.get("require_cnf_jkt_match_inner_key"):
        expected_jkt = hashlib.sha256(inner_key).hexdigest()[:32]
        actual_jkt = (outer_payload.get("cnf") or {}).get("jkt")
        if actual_jkt != expected_jkt:
            return deny("jkt_mismatch")

    # 5. aud / azp exact allow; scope must be allowed.
    if inner_payload.get("aud") not in policy.get("allowed_aud", []):
        return deny("aud_denied")
    if inner_payload.get("azp") not in policy.get("allowed_azp", []):
        return deny("azp_denied")
    if inner_payload.get("scope") not in policy.get("allowed_scopes", []):
        return deny("scope_denied")

    # 6. crit: every member whitelisted and present as a header param.
    crit = inner_header.get("crit")
    if crit is not None:
        allowed_crit = policy.get("allowed_crit", [])
        for member in crit:
            if member not in allowed_crit:
                return deny("crit_unknown")
            if member not in inner_header:
                return deny("crit_param_missing")

    # 7. Time window: inner iat/exp with skew; outer exp as well.
    skew = int(policy.get("clock_skew_seconds", 0))
    inner_iat = inner_payload.get("iat")
    inner_exp = inner_payload.get("exp")
    if inner_iat is not None and now_unix < int(inner_iat) - skew:
        return deny("inner_not_yet_valid")
    if inner_exp is not None and now_unix > int(inner_exp) + skew:
        return deny("inner_expired")
    outer_exp = outer_payload.get("exp")
    if outer_exp is not None and now_unix > int(outer_exp) + skew:
        return deny("outer_expired")

    # 8. Nonce replay store; written only on allow.
    nonce = outer_payload.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return deny("nonce_missing")
    items = store.setdefault("items", {})
    if nonce in items:
        return deny("replay")
    items[nonce] = {"ts": now_unix}

    return {
        "decision": "allow",
        "reason_codes": [],
        "sub": report_sub,
        "aud": report_aud,
    }
