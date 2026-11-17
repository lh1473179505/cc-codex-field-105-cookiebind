from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_notice(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "notice_type": obj.get("notice_type"),
        "source_script": obj.get("source_script"),
        "severity": obj.get("severity"),
        "action": obj.get("action"),
        "field_names": obj.get("field_names"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{notice_type}|{source_script}|{severity}|{action}|{fields}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        notice_type=obj.get("notice_type"),
        source_script=obj.get("source_script"),
        severity=obj.get("severity"),
        action=obj.get("action"),
        fields=",".join(obj.get("field_names") or []),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _source_script_safe(script: Any, policy: dict) -> bool:
    if not isinstance(script, str) or not script:
        return False
    if not script.endswith(policy.get("script_suffix", "")):
        return False
    for bad in policy.get("script_deny_substrings", []):
        if bad and bad in script:
            return False
    parts = script.split("/")
    if any(part in ("", ".", "..") for part in parts):
        return False
    return True

def admit_notice(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    notice_type = obj.get("notice_type")

    def deny(code: str) -> dict:
        return {"decision": "deny", "reason_codes": [code], "notice_type": notice_type}

    spec = (policy.get("notice_types") or {}).get(notice_type)
    if spec is None:
        return deny("notice_type_unknown")

    source_script = obj.get("source_script")
    if not _source_script_safe(source_script, policy):
        return deny("source_script_unsafe")
    if source_script not in (spec.get("source_scripts") or []):
        return deny("source_script_binding")

    if obj.get("severity") not in (spec.get("severities") or []):
        return deny("severity_not_allowed")
    if obj.get("action") not in (spec.get("actions") or []):
        return deny("action_not_allowed")

    fields = obj.get("field_names")
    if not isinstance(fields, list) or any(not isinstance(f, str) for f in fields):
        return deny("field_names_invalid")
    if not (policy.get("field_count_min", 0) <= len(fields) <= policy.get("field_count_max", 0)):
        return deny("field_count")
    if len(set(fields)) != len(fields):
        return deny("field_duplicate")
    allowed = set(spec.get("fields_allowed") or [])
    if any(f not in allowed for f in fields):
        return deny("field_not_allowed")
    if any(f not in fields for f in (spec.get("fields_required") or [])):
        return deny("field_required_missing")

    kid = obj.get("kid")
    key = (keys.get("keys") or {}).get(kid)
    if key is None:
        return deny("key_unknown")
    if key.get("status") != "active":
        return deny("key_revoked")

    sig = obj.get("sig")
    if not isinstance(sig, str) or not hmac.compare_digest(sig, _expected_sig(key["secret"], _signing_line(obj))):
        return deny("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        return deny("iat_invalid")
    if iat > now_unix + policy.get("clock_skew_seconds", 0):
        return deny("iat_future")
    if now_unix - iat > policy.get("max_age_seconds", 0):
        return deny("iat_stale")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return deny("nonce_invalid")
    items = store.setdefault("items", {})
    if nonce in items:
        return deny("nonce_replay")

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "notice_type": notice_type}
