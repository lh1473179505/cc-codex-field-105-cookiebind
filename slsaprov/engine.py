from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

_HEX_LOWER = set("0123456789abcdef")


def inspect_provenance(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "builder": obj.get("builder"),
        "repo_ref": obj.get("repo_ref"),
        "source_digest": obj.get("source_digest"),
        "subject": obj.get("subject"),
        "subject_digest": obj.get("subject_digest"),
        "build_level": obj.get("build_level"),
        "nonce": obj.get("nonce"),
    }

def _is_hex(value: Any, length: int, lowercase: bool) -> bool:
    if not isinstance(value, str) or len(value) != length:
        return False
    allowed = _HEX_LOWER if lowercase else set("0123456789abcdefABCDEF")
    return all(c in allowed for c in value)

def _mac_string(obj: dict) -> str:
    return "v1|{kid}|{builder}|{repo_ref}|{source_digest}|{subject}|{subject_digest}|{build_level}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        builder=obj.get("builder"),
        repo_ref=obj.get("repo_ref"),
        source_digest=obj.get("source_digest"),
        subject=obj.get("subject"),
        subject_digest=obj.get("subject_digest"),
        build_level=obj.get("build_level"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def admit_provenance(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []
    subject = obj.get("subject")

    builders = policy.get("builders", {})
    builder = obj.get("builder")
    builder_cfg = builders.get(builder) if isinstance(builder, str) else None
    if builder_cfg is None:
        codes.append("builder_not_allowed")

    repo_ref = obj.get("repo_ref")
    ref_ok = False
    if isinstance(repo_ref, str):
        for bad in policy.get("repo_ref_deny_substrings", []):
            if bad and bad in repo_ref:
                codes.append("repo_ref_denied_substring")
                break
        if builder_cfg is not None:
            if repo_ref in builder_cfg.get("repo_refs", []):
                ref_ok = True
            else:
                codes.append("repo_ref_not_allowed")
    else:
        codes.append("repo_ref_not_allowed")

    src_len = int(policy.get("source_digest_hex_len", 64))
    sub_len = int(policy.get("subject_digest_hex_len", 64))
    lower = bool(policy.get("require_lowercase_hex", True))
    if not _is_hex(obj.get("source_digest"), src_len, lower):
        codes.append("source_digest_invalid")
    if not _is_hex(obj.get("subject_digest"), sub_len, lower):
        codes.append("subject_digest_invalid")

    if builder_cfg is not None and ref_ok:
        namespaces = builder_cfg.get("repo_subjects", {}).get(repo_ref, [])
        if not isinstance(subject, str) or not any(subject.startswith(ns) for ns in namespaces):
            codes.append("subject_namespace_not_allowed")
        elif policy.get("require_subject_name", True) and not any(
            subject.startswith(ns) and len(subject) > len(ns) for ns in namespaces
        ):
            codes.append("subject_name_empty")

    level = obj.get("build_level")
    if builder_cfg is not None:
        if not isinstance(level, int) or isinstance(level, bool) or level not in builder_cfg.get("build_levels", []):
            codes.append("build_level_not_allowed")

    key_ok = False
    kid = obj.get("kid")
    key_entry = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        codes.append("key_unknown")
    elif key_entry.get("status") != "active":
        codes.append("key_revoked")
    else:
        key_ok = True

    if key_ok:
        try:
            secret = bytes.fromhex(key_entry["secret"])
        except (ValueError, KeyError, TypeError):
            codes.append("key_unknown")
        else:
            expected = base64.urlsafe_b64encode(
                hmac.new(secret, _mac_string(obj).encode("utf-8"), hashlib.sha256).digest()
            ).rstrip(b"=").decode("ascii")
            sig = obj.get("sig")
            if not isinstance(sig, str) or not hmac.compare_digest(expected, sig):
                codes.append("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        codes.append("iat_invalid")
    else:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat - now_unix > skew:
            codes.append("iat_future")
        elif now_unix - iat > max_age:
            codes.append("iat_stale")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        codes.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        codes.append("nonce_replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "subject": subject}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "subject": subject}
