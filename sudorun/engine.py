from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_command(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "group": obj.get("group"),
        "host": obj.get("host"),
        "command": obj.get("command"),
        "args_sha256": obj.get("args_sha256"),
        "noexec": obj.get("noexec"),
        "nonce": obj.get("nonce"),
    }

def _canonical_command(command: Any) -> bool:
    if not isinstance(command, str) or not command.startswith("/"):
        return False
    if "\\" in command or "\x00" in command:
        return False
    parts = command.split("/")
    for part in parts[1:]:
        if part in ("", ".", ".."):
            return False
    return True

def _valid_args_digest(digest: Any, policy: dict) -> bool:
    if not isinstance(digest, str):
        return False
    if len(digest) != policy.get("args_sha256_hex_len", 64):
        return False
    if policy.get("require_lowercase_hex", True):
        return all(c in "0123456789abcdef" for c in digest)
    return all(c in "0123456789abcdefABCDEF" for c in digest)

def _signing_line(obj: dict) -> str:
    return "v1|{}|{}|{}|{}|{}|{}|{}|{}|{}".format(
        obj.get("kid"), obj.get("user"), obj.get("group"), obj.get("host"),
        obj.get("command"), obj.get("args_sha256"), obj.get("noexec"),
        obj.get("iat"), obj.get("nonce"),
    )

def admit_command(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    user_name = obj.get("user")

    users = policy.get("users", {})
    user = users.get(user_name)
    if user is None:
        reasons.append("user_unknown")
        command_rule = None
    else:
        group = obj.get("group")
        host = obj.get("host")
        if group not in user.get("groups", []):
            reasons.append("group_not_allowed")
        if host not in user.get("hosts", []):
            reasons.append("host_not_allowed")
        command = obj.get("command")
        if not _canonical_command(command):
            reasons.append("command_not_canonical")
            command_rule = None
        else:
            command_rule = user.get("commands", {}).get(command)
            if command_rule is None:
                reasons.append("command_not_allowed")
            else:
                if group not in command_rule.get("groups", []):
                    reasons.append("command_group_not_allowed")
                if host not in command_rule.get("hosts", []):
                    reasons.append("command_host_not_allowed")

    digest = obj.get("args_sha256")
    if not _valid_args_digest(digest, policy):
        reasons.append("args_sha256_malformed")
    elif command_rule is not None and digest != command_rule.get("args_sha256"):
        reasons.append("args_sha256_mismatch")

    if obj.get("noexec") != policy.get("require_noexec"):
        reasons.append("noexec_mismatch")

    key = keys.get("keys", {}).get(obj.get("kid"))
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        if iat - now_unix > policy.get("clock_skew_seconds", 0):
            reasons.append("iat_in_future")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replayed")

    if key is not None and key.get("status") == "active":
        try:
            secret = bytes.fromhex(key.get("secret", ""))
        except ValueError:
            secret = b""
        expected = hmac.new(secret, _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
        provided = obj.get("sig")
        provided_bytes = None
        if isinstance(provided, str):
            try:
                provided_bytes = base64.urlsafe_b64decode(provided + "=" * (-len(provided) % 4))
            except ValueError:
                provided_bytes = None
        if provided_bytes is None or not hmac.compare_digest(expected, provided_bytes):
            reasons.append("bad_signature")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "user": user_name}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "user": user_name}
