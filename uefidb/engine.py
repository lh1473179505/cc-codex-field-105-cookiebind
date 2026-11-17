from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

_OWNER_GUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_LOWER_HEX_RE = re.compile(r"[0-9a-f]*\Z")
_HEX_RE = re.compile(r"[0-9a-fA-F]*\Z")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _signing_line(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj.get("kid")),
        str(obj.get("db")),
        str(obj.get("owner_guid")),
        str(obj.get("cert_digest")),
        str(obj.get("action")),
        str(obj.get("append")),
        str(obj.get("auth")),
        str(obj.get("iat")),
        str(obj.get("nonce")),
    ])

def inspect_update(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "db": obj.get("db"),
        "owner_guid": obj.get("owner_guid"),
        "cert_digest": obj.get("cert_digest"),
        "action": obj.get("action"),
        "append": obj.get("append"),
        "auth": obj.get("auth"),
        "nonce": obj.get("nonce"),
    }

def admit_update(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    db = obj.get("db") if isinstance(obj, dict) else None

    def deny(code: str) -> dict:
        return {"decision": "deny", "reason_codes": [code], "db": db}

    if not isinstance(obj, dict):
        return deny("shape")

    dbs = policy.get("dbs") or {}
    if not isinstance(db, str) or db not in dbs or not isinstance(dbs[db], dict):
        return deny("db")
    db_policy = dbs[db]

    # owner_guid: canonical lowercase UUID, not forbidden, bound to this db.
    owner_guid = obj.get("owner_guid")
    if not isinstance(owner_guid, str) or _OWNER_GUID_RE.fullmatch(owner_guid) is None:
        return deny("owner_syntax")
    if owner_guid in (policy.get("forbidden_owner_guids") or []):
        return deny("owner_forbidden")
    if owner_guid != db_policy.get("owner_guid"):
        return deny("owner_binding")

    # cert_digest: exact lowercase hex length; zero only when policy allows.
    cert_digest = obj.get("cert_digest")
    digest_hex_len = policy.get("digest_hex_len", 64)
    if not isinstance(cert_digest, str) or len(cert_digest) != digest_hex_len:
        return deny("digest_length")
    hex_re = _LOWER_HEX_RE if policy.get("require_lowercase_hex", True) else _HEX_RE
    hex_ok = hex_re.fullmatch(cert_digest) is not None
    if not hex_ok:
        return deny("digest_syntax")
    if policy.get("forbid_zero_digest", False) and set(cert_digest) == {"0"}:
        return deny("digest_zero")

    # action must be one of the selected db actions.
    action = obj.get("action")
    if action not in (db_policy.get("actions") or []):
        return deny("action")

    # append must be an allowed integer and bound to the action.
    append = obj.get("append")
    if not _is_int(append) or append not in (policy.get("append_values") or []):
        return deny("append_value")
    if append != (db_policy.get("append_by_action") or {}).get(action):
        return deny("append_binding")

    # auth must pass both the db layer and the action layer.
    auth = obj.get("auth")
    if auth not in (db_policy.get("auth_methods") or []):
        return deny("auth_method")
    if auth not in ((db_policy.get("auth_by_action") or {}).get(action) or []):
        return deny("auth_action")

    # The signing key must exist and be active; a revoked key denies even
    # when the HMAC itself verifies.
    kid = obj.get("kid")
    key_entry = (keys.get("keys") or {}).get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        return deny("unknown_key")
    if key_entry.get("status") != "active":
        return deny("key_revoked")

    # Recompute the complete v1 signing line and verify the HMAC.
    iat = obj.get("iat")
    nonce = obj.get("nonce")
    if not _is_int(iat) or not isinstance(nonce, str) or not nonce:
        return deny("bad_signature")
    try:
        secret = bytes.fromhex(key_entry["secret"])
        expected = hmac.new(
            secret, _signing_line(obj).encode("utf-8"), hashlib.sha256
        ).digest()
        try:
            provided = _b64url_decode(str(obj.get("sig", "")))
        except Exception:
            provided = b""
    except (ValueError, KeyError, TypeError):
        return deny("bad_signature")
    if not hmac.compare_digest(expected, provided):
        return deny("bad_signature")

    # iat must be no older than max_age and no more than skew in the future.
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if iat > now_unix + skew or now_unix - iat > max_age:
        return deny("iat_window")

    # Nonce replay protection; only an allow consumes the nonce.
    items = store.get("items")
    if not isinstance(items, dict):
        return deny("store_shape")
    if nonce in items:
        return deny("nonce_replay")

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "db": db}
