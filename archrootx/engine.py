from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_entry(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "archive": obj.get("archive"),
        "entry": obj.get("entry"),
        "link_target": obj.get("link_target"),
        "target_root": obj.get("target_root"),
        "size": obj.get("size"),
        "mode": obj.get("mode"),
        "uid": obj.get("uid"),
        "gid": obj.get("gid"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{archive}|{entry}|{link_target}|{target_root}|{size}|{mode}|{uid}|{gid}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        archive=obj.get("archive"),
        entry=obj.get("entry"),
        link_target=obj.get("link_target"),
        target_root=obj.get("target_root"),
        size=obj.get("size"),
        mode=obj.get("mode"),
        uid=obj.get("uid"),
        gid=obj.get("gid"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_entry(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    entry = obj.get("entry")
    archive = obj.get("archive")
    link_target = obj.get("link_target")
    target_root = obj.get("target_root")
    mode = obj.get("mode")
    nonce = obj.get("nonce")

    # HMAC + revocation
    kid = obj.get("kid")
    key = (keys.get("keys") or {}).get(kid)
    if key is None:
        reasons.append("unknown_key")
    else:
        if key.get("status") != "active":
            reasons.append("key_revoked")
        expected = _expected_sig(key.get("secret", ""), _signing_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_sig")

    # Time window
    try:
        iat = int(obj.get("iat"))
    except (TypeError, ValueError):
        iat = None
        reasons.append("bad_iat")
    if iat is not None:
        if iat > now_unix + int(policy.get("clock_skew_seconds", 0)):
            reasons.append("iat_in_future")
        if iat < now_unix - int(policy.get("max_age_seconds", 0)):
            reasons.append("expired")

    # Nonce: allow-only (replay deny)
    if not nonce:
        reasons.append("missing_nonce")
    elif nonce in (store.get("items") or {}):
        reasons.append("nonce_replay")

    # Archive suffix
    suffixes = policy.get("archive_suffixes") or []
    if not isinstance(archive, str) or not any(archive.endswith(s) for s in suffixes):
        reasons.append("archive_suffix")

    # Entry path
    if not isinstance(entry, str) or not entry:
        reasons.append("bad_entry")
    else:
        if policy.get("forbid_absolute_entry") and (entry.startswith("/") or entry.startswith("~")):
            reasons.append("entry_absolute")
        for sub in policy.get("entry_deny_substrings") or []:
            if sub and sub in entry:
                reasons.append("entry_denied")
                break

    # Symlink / hardlink modes
    if policy.get("forbid_symlink") and mode in (policy.get("symlink_modes") or []):
        reasons.append("symlink_forbidden")
    if policy.get("forbid_hardlink") and mode in (policy.get("hardlink_modes") or []):
        reasons.append("hardlink_forbidden")

    # Non-link entries require empty link_target
    is_link = mode in (policy.get("symlink_modes") or []) or mode in (policy.get("hardlink_modes") or [])
    if policy.get("link_target_must_empty_unless_link") and not is_link and link_target:
        reasons.append("link_target_not_empty")

    # Root binding: uid/gid/mode/size per target_root
    roots = policy.get("roots") or {}
    root = roots.get(target_root)
    if root is None:
        reasons.append("root_not_allowed")
    else:
        if obj.get("uid") not in (root.get("uid_allow") or []):
            reasons.append("uid_not_allowed")
        if obj.get("gid") not in (root.get("gid_allow") or []):
            reasons.append("gid_not_allowed")
        if mode not in (root.get("mode_allow") or []):
            reasons.append("mode_not_allowed")
        size = obj.get("size")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0 or size > int(root.get("max_size", 0)):
            reasons.append("size_not_allowed")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "entry": entry}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "entry": entry}
