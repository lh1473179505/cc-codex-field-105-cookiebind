from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_job(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "schedule": obj.get("schedule"),
        "shell": obj.get("shell"),
        "cmd": obj.get("cmd"),
        "cwd": obj.get("cwd"),
        "env": obj.get("env"),
        "umask": obj.get("umask"),
        "nonce": obj.get("nonce"),
    }

_STR_FIELDS = ("user", "schedule", "shell", "cmd", "cwd", "env", "umask", "nonce", "kid", "sig")

def _expected_sig(line: str, secret_hex: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_job(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    cmd = obj.get("cmd") if isinstance(obj.get("cmd"), str) else ""
    reasons: list[str] = []

    vals: dict[str, str] = {}
    bad_shape = False
    for name in _STR_FIELDS:
        v = obj.get(name)
        if not isinstance(v, str) or not v:
            bad_shape = True
            v = ""
        vals[name] = v
    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        bad_shape = True
        iat = 0
    if bad_shape:
        return {"decision": "deny", "reason_codes": ["bad_fields"], "cmd": cmd}

    users = policy.get("users", {})
    u = users.get(vals["user"])
    if u is None:
        reasons.append("user_not_allowed")

    tokens = vals["schedule"].split()
    if len(tokens) != policy.get("schedule_fields", 5):
        reasons.append("schedule_fields")
    elif u is not None:
        try:
            hour = int(tokens[1])
        except ValueError:
            hour = None
        if hour is None or hour not in u.get("sched_hours", []):
            reasons.append("sched_hour")
        dow = tokens[4]
        if (policy.get("forbid_wildcard_dow") and dow == "*") or dow not in u.get("sched_dows", []):
            reasons.append("sched_dow")

    if u is not None and vals["shell"] not in u.get("shells", []):
        reasons.append("shell_not_allowed")

    if any(sub in cmd for sub in policy.get("cmd_deny_substrings", [])):
        reasons.append("cmd_deny_substring")
    if u is not None and not any(cmd.startswith(p) for p in u.get("cmd_prefixes", [])):
        reasons.append("cmd_prefix")

    if any(sub in vals["cwd"] for sub in policy.get("cwd_deny_substrings", [])):
        reasons.append("cwd_deny_substring")
    if u is not None and vals["cwd"] not in u.get("cwd_allow", []):
        reasons.append("cwd_not_allowed")

    for name in vals["env"].split(","):
        if any(sub in name for sub in policy.get("env_deny_substrings", [])):
            reasons.append("env_deny_substring")
            break
    if u is not None:
        for name in vals["env"].split(","):
            if name not in u.get("env_allow", []):
                reasons.append("env_not_allowed")
                break

    if u is not None and vals["umask"] not in u.get("umask_allow", []):
        reasons.append("umask_not_allowed")

    key = keys.get("keys", {}).get(vals["kid"])
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        line = "v1|{kid}|{user}|{schedule}|{shell}|{cmd}|{cwd}|{env}|{umask}|{iat}|{nonce}".format(
            iat=iat, **vals
        )
        if not hmac.compare_digest(_expected_sig(line, key["secret"]), vals["sig"]):
            reasons.append("bad_sig")

    if iat - now_unix > policy.get("clock_skew_seconds", 0):
        reasons.append("iat_future")
    if now_unix - iat > policy.get("max_age_seconds", 0):
        reasons.append("iat_expired")

    items = store.setdefault("items", {})
    if vals["nonce"] in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "cmd": cmd}
    items[vals["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "cmd": cmd}
