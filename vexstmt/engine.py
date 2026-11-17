from __future__ import annotations
import base64
import hashlib
import hmac
import re
from datetime import datetime, timezone
from typing import Any

_ISSUED_AT_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def inspect_statement(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "product_purl": obj.get("product_purl"),
        "cve": obj.get("cve"),
        "status": obj.get("status"),
        "justification": obj.get("justification"),
        "action_statement": obj.get("action_statement"),
        "issued_at": obj.get("issued_at"),
        "nonce": obj.get("nonce"),
    }


def _parse_issued_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or not _ISSUED_AT_RE.match(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _signature_line(obj: dict) -> str:
    return "v1|{kid}|{product_purl}|{cve}|{status}|{justification}|{action_statement}|{issued_at}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        product_purl=obj.get("product_purl"),
        cve=obj.get("cve"),
        status=obj.get("status"),
        justification=obj.get("justification"),
        action_statement=obj.get("action_statement"),
        issued_at=obj.get("issued_at"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )


def admit_statement(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    product_purl = obj.get("product_purl")

    required = {
        "kid": str, "product_purl": str, "cve": str, "status": str,
        "justification": str, "action_statement": str, "issued_at": str,
        "nonce": str, "sig": str,
    }
    for field, ftype in required.items():
        if not isinstance(obj.get(field), ftype):
            reasons.append("invalid_field")
            break
    if not isinstance(obj.get("iat"), int) or isinstance(obj.get("iat"), bool):
        if "invalid_field" not in reasons:
            reasons.append("invalid_field")
    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "product_purl": product_purl}

    products = policy.get("products", {})
    product = products.get(product_purl)
    cve_entry = None
    if product is None:
        reasons.append("product_unknown")
    else:
        cve = obj["cve"]
        if not re.match(policy.get("cve_pattern", ""), cve):
            reasons.append("cve_format")
        cve_entry = product.get("cves", {}).get(cve)
        if cve_entry is None:
            reasons.append("cve_unknown")

    if cve_entry is not None:
        if obj["status"] not in cve_entry.get("statuses", []):
            reasons.append("status_not_allowed")

        justifications = cve_entry.get("justifications", [])
        if justifications:
            if obj["justification"] not in justifications:
                reasons.append("justification_invalid")
        elif obj["justification"] != "":
            reasons.append("justification_forbidden")

        action = obj["action_statement"]
        if cve_entry.get("action_required"):
            if not action:
                reasons.append("action_required")
            elif not any(action.startswith(p) for p in cve_entry.get("action_prefixes", [])):
                reasons.append("action_prefix")
        elif action != "":
            reasons.append("action_forbidden")
        if len(action) > policy.get("action_length_max", 0):
            reasons.append("action_too_long")

    issued = _parse_issued_at(obj["issued_at"])
    if issued is None:
        reasons.append("issued_at_format")
    else:
        lo = _parse_issued_at(policy.get("issued_at_min"))
        hi = _parse_issued_at(policy.get("issued_at_max"))
        if (lo is not None and issued < lo) or (hi is not None and issued > hi):
            reasons.append("issued_at_range")

    key = keys.get("keys", {}).get(obj["kid"])
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")

    iat = obj["iat"]
    if now_unix - iat > policy.get("max_age_seconds", 0):
        reasons.append("iat_stale")
    if iat - now_unix > policy.get("clock_skew_seconds", 0):
        reasons.append("iat_future")

    if key is not None and key.get("status") == "active":
        try:
            secret = bytes.fromhex(key.get("secret", ""))
        except ValueError:
            secret = b""
        digest = hmac.new(secret, _signature_line(obj).encode("utf-8"), hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, obj["sig"]):
            reasons.append("signature_mismatch")

    if obj["nonce"] in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "product_purl": product_purl}

    store.setdefault("items", {})[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "product_purl": product_purl}
