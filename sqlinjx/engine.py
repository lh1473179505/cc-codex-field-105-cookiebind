from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_query(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "schema": obj.get("schema"),
        "table": obj.get("table"),
        "op": obj.get("op"),
        "params": obj.get("params"),
        "where_cols": obj.get("where_cols"),
        "nonce": obj.get("nonce"),
    }

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _ident_issues(name: Any, deny_subs: list, require_lower: bool) -> list:
    codes = []
    if not isinstance(name, str) or not name:
        return ["ident_invalid"]
    if any(sub in name for sub in deny_subs):
        codes.append("ident_injection")
    if require_lower and name != name.lower():
        codes.append("ident_case")
    return codes

def admit_query(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list = []
    table = obj.get("table")

    kid = obj.get("kid")
    schema = obj.get("schema")
    op = obj.get("op")
    params = obj.get("params")
    where_cols_raw = obj.get("where_cols")
    iat = obj.get("iat")
    nonce = obj.get("nonce")
    sig = obj.get("sig")

    deny_subs = policy.get("ident_deny_substrings", [])
    require_lower = bool(policy.get("require_lowercase_idents", False))

    if not isinstance(params, list):
        reasons.append("params_invalid")
        params = []
    if not isinstance(where_cols_raw, str):
        reasons.append("where_cols_invalid")
        where_cols_raw = ""
    where_cols = [c for c in where_cols_raw.split(",") if c != ""]

    reasons.extend(_ident_issues(op, deny_subs, False))
    for value in (schema, table):
        reasons.extend(_ident_issues(value, deny_subs, require_lower))
    for col in where_cols:
        reasons.extend(_ident_issues(col, deny_subs, require_lower))

    schemas = policy.get("schemas", {})
    schema_cfg = schemas.get(schema) if isinstance(schema, str) else None
    if schema_cfg is None:
        reasons.append("schema_not_allowed")
        schema_cfg = {}
    else:
        if table not in schema_cfg.get("tables", []):
            reasons.append("table_not_allowed")
        if op not in schema_cfg.get("ops", []):
            reasons.append("op_not_allowed")
        where_allow = schema_cfg.get("where_allow", [])
        for col in where_cols:
            if col not in where_allow:
                reasons.append("where_col_not_allowed")

    if len(where_cols) > int(policy.get("where_cols_csv_max", 0)):
        reasons.append("where_cols_too_many")
    if len(params) > int(policy.get("params_max", 0)):
        reasons.append("params_too_many")

    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_invalid")
        iat = 0
    else:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat > now_unix + skew:
            reasons.append("iat_future")
        if now_unix - iat > max_age:
            reasons.append("iat_expired")

    key_entry = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        reasons.append("key_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    if key_entry is not None and isinstance(sig, str):
        try:
            secret = bytes.fromhex(key_entry.get("secret", ""))
        except ValueError:
            secret = b""
        line = "v1|{}|{}|{}|{}|{}|{}|{}|{}".format(
            kid, schema, table, op, ",".join(str(p) for p in params),
            where_cols_raw, iat, nonce,
        )
        expected = _b64url(hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest())
        if not hmac.compare_digest(expected, sig):
            reasons.append("bad_signature")
    elif not isinstance(sig, str):
        reasons.append("bad_signature")

    items = store.get("items")
    if not isinstance(items, dict):
        items = {}
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": sorted(set(reasons)), "table": table}

    items = store.setdefault("items", {})
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "table": table}
