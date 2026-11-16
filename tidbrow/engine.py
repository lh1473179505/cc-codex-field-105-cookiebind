from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_row(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "tenant": obj.get("tenant"),
        "table": obj.get("table"),
        "op": obj.get("op"),
        "pred": obj.get("pred"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{tenant}|{table}|{op}|{pred}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        tenant=obj.get("tenant"),
        table=obj.get("table"),
        op=obj.get("op"),
        pred=obj.get("pred"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_row(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []
    tenant = obj.get("tenant")

    required = ("kid", "tenant", "table", "op", "pred", "nonce", "iat", "sig")
    if any(obj.get(f) is None for f in required):
        codes.append("missing_field")

    tpol = (policy.get("tenants") or {}).get(tenant)
    if tpol is None:
        codes.append("tenant_unknown")
    else:
        if obj.get("table") not in (tpol.get("tables") or []):
            codes.append("table_denied")
        if obj.get("op") not in (tpol.get("ops") or []):
            codes.append("op_denied")
        pred = obj.get("pred")
        if isinstance(pred, str):
            cols = [c for c in pred.split(",") if c != ""]
            allow = set(tpol.get("pred_allow") or [])
            require = set(tpol.get("pred_require") or [])
            if not require.issubset(set(cols)):
                codes.append("pred_required_missing")
            if any(c not in allow for c in cols):
                codes.append("pred_not_allowed")
            for bad in policy.get("pred_deny_substrings") or []:
                if bad and bad in pred:
                    codes.append("pred_injection")
                    break

    key = (keys.get("keys") or {}).get(obj.get("kid"))
    if key is None:
        codes.append("kid_unknown")
    else:
        if key.get("status") != "active":
            codes.append("key_revoked")
        else:
            try:
                expected = _expected_sig(key["secret"], _signing_line(obj))
            except (ValueError, KeyError):
                expected = None
            if expected is None or not hmac.compare_digest(expected, str(obj.get("sig"))):
                codes.append("bad_sig")

    iat = obj.get("iat")
    if isinstance(iat, int) and not isinstance(iat, bool):
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat - now_unix > skew:
            codes.append("iat_future")
        elif now_unix - iat > max_age:
            codes.append("iat_expired")
    else:
        codes.append("iat_invalid")

    nonce = obj.get("nonce")
    items = store.get("items") or {}
    if nonce in items:
        codes.append("nonce_replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "tenant": tenant}
    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "tenant": tenant}
