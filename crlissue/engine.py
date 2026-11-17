from __future__ import annotations
import base64
import hashlib
import hmac
import re
from datetime import datetime, timezone
from typing import Any

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _parse_canonical_utc(value: Any) -> int | None:
    if not isinstance(value, str) or not _TS_RE.match(value):
        return None
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int(dt.timestamp())


def _signed_line(obj: dict) -> str:
    reasons_raw = obj.get("reasons")
    if isinstance(reasons_raw, list) and all(isinstance(r, str) for r in reasons_raw):
        reasons = ",".join(reasons_raw)
    else:
        reasons = ""
    return "v1|{kid}|{issuer}|{signature_alg}|{crl_number}|{this_update}|{next_update}|{reasons}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        issuer=obj.get("issuer"),
        signature_alg=obj.get("signature_alg"),
        crl_number=obj.get("crl_number"),
        this_update=obj.get("this_update"),
        next_update=obj.get("next_update"),
        reasons=reasons,
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )


def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def inspect_crl(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "issuer": obj.get("issuer"),
        "signature_alg": obj.get("signature_alg"),
        "crl_number": obj.get("crl_number"),
        "this_update": obj.get("this_update"),
        "next_update": obj.get("next_update"),
        "reasons": obj.get("reasons"),
        "nonce": obj.get("nonce"),
    }

def admit_crl(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []
    issuer = obj.get("issuer")

    issuers = policy.get("issuers") or {}
    ipolicy = issuers.get(issuer)
    if ipolicy is None:
        codes.append("issuer_unknown")

    if ipolicy is not None:
        if obj.get("signature_alg") not in (ipolicy.get("signature_algs") or []):
            codes.append("signature_alg_not_allowed")

        crl_number = obj.get("crl_number")
        if isinstance(crl_number, bool) or not isinstance(crl_number, int):
            codes.append("crl_number_not_integer")
        elif not (ipolicy["crl_number_min"] <= crl_number <= ipolicy["crl_number_max"]):
            codes.append("crl_number_out_of_range")

        this_ts = _parse_canonical_utc(obj.get("this_update"))
        next_ts = _parse_canonical_utc(obj.get("next_update"))
        if this_ts is None:
            codes.append("this_update_format")
        if next_ts is None:
            codes.append("next_update_format")
        if this_ts is not None and next_ts is not None:
            if next_ts <= this_ts:
                codes.append("update_order")
            elif next_ts - this_ts != ipolicy["validity_seconds"]:
                codes.append("validity_seconds_mismatch")

        reasons = obj.get("reasons")
        allowed = ipolicy.get("reasons_allowed") or []
        if not isinstance(reasons, list) or any(not isinstance(r, str) for r in reasons):
            codes.append("reasons_not_string_array")
        else:
            if any(r not in allowed for r in reasons):
                codes.append("reason_not_allowed")
            if policy.get("require_unique_reasons") and len(set(reasons)) != len(reasons):
                codes.append("reason_duplicate")
            if len(reasons) > policy.get("max_reasons", 0):
                codes.append("reason_count_exceeded")

    key_entry = (keys.get("keys") or {}).get(obj.get("kid"))
    if key_entry is None:
        codes.append("key_unknown")
    elif key_entry.get("status") != "active":
        codes.append("key_not_active")

    iat = obj.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int):
        codes.append("iat_not_integer")
    else:
        if now_unix - iat > policy.get("max_age_seconds", 0):
            codes.append("iat_stale")
        if iat - now_unix > policy.get("clock_skew_seconds", 0):
            codes.append("iat_future_skew")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        codes.append("nonce_invalid")
    elif nonce in (store.get("items") or {}):
        codes.append("nonce_replay")

    if key_entry is not None and isinstance(obj.get("sig"), str):
        if not hmac.compare_digest(_expected_sig(key_entry["secret"], _signed_line(obj)), obj["sig"]):
            codes.append("signature_mismatch")
    else:
        codes.append("signature_mismatch")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "issuer": issuer}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "issuer": issuer}
