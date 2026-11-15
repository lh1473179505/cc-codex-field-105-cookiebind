from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

SIGNING_VERSION = "v1"

_QUERY_FIELDS = ("kid", "bind_dn", "base_dn", "filter", "scope", "nonce", "sig")

def inspect_query(query: dict) -> dict:
    return {
        "kid": query.get("kid"),
        "bind_dn": query.get("bind_dn"),
        "base_dn": query.get("base_dn"),
        "filter": query.get("filter"),
        "scope": query.get("scope"),
        "nonce": query.get("nonce"),
    }

def _dn_suffix_match(dn: str, suffix: str) -> bool:
    """Exact suffix match on a DN component boundary, case-sensitive as stored."""
    if not suffix:
        return True
    if not dn.endswith(suffix):
        return False
    if suffix.startswith(",") or len(dn) == len(suffix):
        return True
    return dn[-len(suffix) - 1] == ","

def _signing_payload(query: dict) -> bytes:
    return "|".join((
        SIGNING_VERSION,
        query["kid"],
        query["bind_dn"],
        query["base_dn"],
        query["filter"],
        query["scope"],
        query["nonce"],
    )).encode("utf-8")

def _expected_signature(secret_hex: str, payload: bytes) -> str:
    secret = bytes.fromhex(secret_hex)
    digest = hmac.new(secret, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

def _filter_depth(flt: str) -> int:
    depth = 0
    worst = 0
    for ch in flt:
        if ch == "(":
            depth += 1
            if depth > worst:
                worst = depth
        elif ch == ")":
            depth -= 1
    return worst

def _filter_attributes(flt: str) -> list[str]:
    attrs: list[str] = []
    for token in flt.split("(")[1:]:
        if not token or token[0] in "&|!":
            continue
        name = token.split("=", 1)[0].strip()
        if name:
            attrs.append(name)
    return attrs

def admit_query(query: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    bind_dn = query.get("bind_dn") if isinstance(query.get("bind_dn"), str) else ""
    base_dn = query.get("base_dn") if isinstance(query.get("base_dn"), str) else ""
    report: dict[str, Any] = {
        "decision": "deny",
        "reason_codes": [],
        "bind_dn": bind_dn,
        "base_dn": base_dn,
    }

    if not all(isinstance(query.get(field), str) and query.get(field) for field in _QUERY_FIELDS):
        report["reason_codes"].append("malformed_query")
        return report

    reasons: list[str] = []

    key_entry = keys.get("keys", {}).get(query["kid"])
    if key_entry is None:
        reasons.append("unknown_kid")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        try:
            expected = _expected_signature(key_entry["secret"], _signing_payload(query))
        except (ValueError, TypeError):
            expected = ""
        if not expected or not hmac.compare_digest(expected, query["sig"]):
            reasons.append("bad_signature")

    if not _dn_suffix_match(query["bind_dn"], policy.get("allowed_bind_dn_suffix", "")):
        reasons.append("bind_dn_suffix")
    if not _dn_suffix_match(query["base_dn"], policy.get("allowed_base_dn_suffix", "")):
        reasons.append("base_dn_suffix")
    if policy.get("require_bind_under_base", False) and not _dn_suffix_match(query["bind_dn"], query["base_dn"]):
        reasons.append("bind_not_under_base")

    if query["scope"] not in policy.get("allowed_scopes", []):
        reasons.append("scope_not_allowed")

    flt = query["filter"]
    if len(flt) > policy.get("max_filter_length", 0):
        reasons.append("filter_too_long")
    if _filter_depth(flt) > policy.get("max_filter_depth", 0):
        reasons.append("filter_depth")

    allowed_attrs = {attr.lower() for attr in policy.get("allowed_attributes", [])}
    if any(attr.lower() not in allowed_attrs for attr in _filter_attributes(flt)):
        reasons.append("attribute_not_allowed")

    if any(token and token in flt for token in policy.get("forbidden_filter_tokens", [])):
        reasons.append("filter_injection")

    items = store.get("items", {})
    if not isinstance(items, dict) or query["nonce"] in items:
        reasons.append("nonce_replay")

    if reasons:
        report["reason_codes"] = reasons
        return report

    items = store.setdefault("items", {})
    items[query["nonce"]] = {"ts": now_unix}
    report["decision"] = "allow"
    return report
