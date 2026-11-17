from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_action(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "subject": obj.get("subject"),
        "action": obj.get("action"),
        "auth": obj.get("auth"),
        "annotations": obj.get("annotations"),
        "session": obj.get("session"),
        "nonce": obj.get("nonce"),
    }

def _render_mapping(m: Any) -> str:
    return ",".join(f"{k}={m[k]}" for k in sorted(m))

def _signing_line(obj: dict) -> str:
    return "v1|{}|{}|{}|{}|{}|{}|{}|{}".format(
        obj.get("kid"),
        obj.get("subject"),
        obj.get("action"),
        _render_mapping(obj.get("auth") or {}),
        _render_mapping(obj.get("annotations") or {}),
        _render_mapping(obj.get("session") or {}),
        obj.get("iat"),
        obj.get("nonce"),
    )

def admit_action(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    action_name = obj.get("action")

    key_entry = (keys.get("keys") or {}).get(obj.get("kid"))
    if key_entry is None:
        reasons.append("unknown_key")
    elif key_entry.get("status") != "active":
        reasons.append("key_not_active")

    if key_entry is not None:
        secret = bytes.fromhex(key_entry.get("secret", ""))
        expected = base64.urlsafe_b64encode(
            hmac.new(secret, _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat > now_unix + policy.get("clock_skew_seconds", 0):
            reasons.append("iat_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_stale")

    action = (policy.get("actions") or {}).get(action_name)
    if action is None:
        reasons.append("unknown_action")
    else:
        subject = obj.get("subject")
        if not isinstance(subject, str) or not re.fullmatch(policy.get("subject_pattern", ""), subject):
            reasons.append("subject_shape")
        elif subject not in action.get("subjects", []):
            reasons.append("subject_binding")

        if obj.get("auth") != action.get("auth"):
            reasons.append("auth_mismatch")

        annotations = obj.get("annotations")
        if not isinstance(annotations, dict):
            reasons.append("annotations_shape")
        else:
            allowed = set(action.get("annotations_allowed", []))
            if any(k not in allowed for k in annotations):
                reasons.append("annotation_extra")
            for k, v in (action.get("annotations_required") or {}).items():
                if k not in annotations:
                    reasons.append("annotation_required")
                elif annotations[k] != v:
                    reasons.append("annotation_value")

        session = obj.get("session")
        if not isinstance(session, dict) or set(session) != {"type", "active", "local"}:
            reasons.append("session_shape")
        else:
            if session["type"] not in action.get("session_types", []):
                reasons.append("session_type")
            if session["active"] != action.get("require_active"):
                reasons.append("session_inactive")
            if session["local"] != action.get("require_local"):
                reasons.append("session_remote")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in items:
        reasons.append("replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "action": action_name}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "action": action_name}
