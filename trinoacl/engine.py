from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_q(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "catalog": obj.get("catalog"),
        "schema": obj.get("schema"),
        "table": obj.get("table"),
        "user": obj.get("user"),
        "nonce": obj.get("nonce"),
    }

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def _signing_line(kid, catalog, schema, table, user, iat, nonce) -> bytes:
    return f"v1|{kid}|{catalog}|{schema}|{table}|{user}|{iat}|{nonce}".encode("utf-8")

def admit_q(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    catalog = obj.get("catalog")
    report = {"decision": "deny", "reason_codes": [], "catalog": catalog}

    def deny(code: str) -> dict:
        report["reason_codes"].append(code)
        return report

    fields = {k: obj.get(k) for k in ("kid", "catalog", "schema", "table", "user", "nonce", "sig")}
    if any(not isinstance(v, str) or not v for v in fields.values()):
        return deny("malformed")
    iat = obj.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, int):
        return deny("malformed")

    ident_deny = policy.get("ident_deny", [])
    for ident in (fields["schema"], fields["table"]):
        if any(tok and tok in ident for tok in ident_deny):
            return deny("ident_deny")

    key_entry = keys.get("keys", {}).get(fields["kid"])
    if key_entry is None:
        return deny("unknown_kid")
    if key_entry.get("status") != "active":
        return deny("key_revoked")
    try:
        secret = bytes.fromhex(key_entry["secret"])
    except (KeyError, ValueError):
        return deny("bad_key")
    expected = hmac.new(
        secret,
        _signing_line(fields["kid"], catalog, fields["schema"], fields["table"],
                      fields["user"], iat, fields["nonce"]),
        hashlib.sha256,
    ).digest()
    try:
        provided = _b64url_decode(fields["sig"])
    except ValueError:
        return deny("bad_sig")
    if not hmac.compare_digest(expected, provided):
        return deny("bad_sig")

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if iat > now_unix + skew or now_unix - iat > max_age:
        return deny("stale_iat")

    users = policy.get("users", {})
    user_policy = users.get(fields["user"])
    if user_policy is None:
        return deny("unknown_user")
    if catalog not in user_policy.get("catalogs", []):
        return deny("catalog_deny")
    if fields["schema"] not in user_policy.get("schemas", {}).get(catalog, []):
        return deny("schema_deny")
    table_key = f"{catalog}.{fields['schema']}"
    if fields["table"] not in user_policy.get("tables", {}).get(table_key, []):
        return deny("table_deny")

    items = store.setdefault("items", {})
    if fields["nonce"] in items:
        return deny("nonce_replay")

    items[fields["nonce"]] = {"ts": now_unix}
    report["decision"] = "allow"
    return report
