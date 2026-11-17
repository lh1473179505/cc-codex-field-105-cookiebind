from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_query(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "pack": obj.get("pack"),
        "query_name": obj.get("query_name"),
        "sql": obj.get("sql"),
        "tables": obj.get("tables"),
        "interval": obj.get("interval"),
        "platform": obj.get("platform"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    tables = ",".join(obj.get("tables") or [])
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("pack")),
        str(obj.get("query_name")),
        str(obj.get("sql")),
        tables,
        str(obj.get("interval")),
        str(obj.get("platform")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def _expected_sig(obj: dict, secret_hex: str) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        _signing_line(obj).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _sql_tables(sql: str) -> set:
    return {
        m.group(1).lower()
        for m in re.finditer(r"\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_]*)", sql, re.IGNORECASE)
    }

def _deny_token_hit(sql: str, token: str) -> bool:
    if token.isalnum():
        return re.search(r"\b" + re.escape(token) + r"\b", sql, re.IGNORECASE) is not None
    return token in sql

def admit_query(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    query_name = obj.get("query_name")

    packs = policy.get("packs") or {}
    pack = packs.get(obj.get("pack"))
    if pack is None:
        reasons.append("unknown_pack")
        query = None
    else:
        query = (pack.get("queries") or {}).get(query_name)
        if query is None:
            reasons.append("unknown_query")

    sql = obj.get("sql")
    if not isinstance(sql, str) or not sql.strip():
        reasons.append("sql_empty")
        sql = ""
    elif len(sql) > policy.get("sql_length_max", 0):
        reasons.append("sql_too_long")
    if sql:
        if not re.match(r"^\s*SELECT\b", sql, re.IGNORECASE):
            reasons.append("sql_not_select")
        for token in policy.get("sql_deny_tokens") or []:
            if _deny_token_hit(sql, token):
                reasons.append("sql_deny_token")
                break

    tables = obj.get("tables")
    if not isinstance(tables, list) or not tables:
        reasons.append("table_invalid")
        tables = []
    ident = re.compile(policy.get("identifier_pattern") or r"^[a-z][a-z0-9_]*$")
    if any(not isinstance(t, str) or not ident.match(t) for t in tables):
        reasons.append("table_invalid")
    if len(set(tables)) != len(tables):
        reasons.append("table_duplicate")
    count = len(tables)
    if count < policy.get("table_count_min", 0) or count > policy.get("table_count_max", 0):
        reasons.append("table_count")
    if query is not None:
        allowed = set(query.get("tables") or [])
        if not set(tables) <= allowed:
            reasons.append("table_not_allowed")
    if sql and _sql_tables(sql) != set(tables):
        reasons.append("table_sql_mismatch")

    if query is not None:
        if obj.get("interval") not in (query.get("intervals") or []):
            reasons.append("interval_not_allowed")
        if obj.get("platform") not in (query.get("platforms") or []):
            reasons.append("platform_not_allowed")

    kid = obj.get("kid")
    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append("unknown_key")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        expected = _expected_sig(obj, key_entry.get("secret", ""))
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat - now_unix > policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "query_name": query_name}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "query_name": query_name}
