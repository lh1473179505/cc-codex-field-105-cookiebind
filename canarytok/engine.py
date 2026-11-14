from __future__ import annotations
import base64
import hashlib
import hmac
import time
from typing import Any

REASON_INVALID_INPUT = "invalid_input"
REASON_UNKNOWN_KEY = "unknown_key"
REASON_KEY_REVOKED = "key_revoked"
REASON_BAD_SIGNATURE = "bad_signature"
REASON_UNKNOWN_TOKEN = "unknown_token"
REASON_CHANNEL_NOT_ALLOWED = "channel_not_allowed"
REASON_ENV_MISMATCH = "env_mismatch"
REASON_TOKEN_REPLAYED = "token_replayed"
REASON_TIMESTAMP_OUT_OF_WINDOW = "timestamp_out_of_window"

_STRING_FIELDS = ("kid", "token_id", "channel", "env", "sig")


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "canarytok", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def sign_line(kid: str, token_id: str, channel: str, env: str, ts: int) -> str:
    """Canonical signing input per docs/admit-rules.md."""
    return f"v1|{kid}|{token_id}|{channel}|{env}|{ts}"


def expected_signature(secret_hex: str, line: str) -> str:
    secret = bytes.fromhex(secret_hex)
    mac = hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate all admission gates from docs/admit-rules.md.

    Returns the report dict. On allow, and only on allow, the token_id is
    recorded into the passed store mapping (the caller persists it).
    """
    if now_unix is None:
        now_unix = int(time.time())

    if not isinstance(obj, dict):
        return _report("deny", [REASON_INVALID_INPUT], ["input is not an object"])

    if any(not isinstance(obj.get(f), str) or not obj.get(f) for f in _STRING_FIELDS):
        return _report("deny", [REASON_INVALID_INPUT], ["missing or non-string required field"])
    try:
        ts = int(obj.get("ts"))
    except (TypeError, ValueError):
        return _report("deny", [REASON_INVALID_INPUT], ["ts must be a unix integer"])

    kid = obj["kid"]
    token_id = obj["token_id"]
    channel = obj["channel"]
    env = obj["env"]
    sig = obj["sig"]

    reasons: list[str] = []
    notes: list[str] = []

    key_entry = (keys.get("keys") or {}).get(kid)
    if key_entry is None:
        reasons.append(REASON_UNKNOWN_KEY)
        notes.append(f"kid {kid!r} not found in keys")
    else:
        if key_entry.get("status") != "active":
            reasons.append(REASON_KEY_REVOKED)
            notes.append(f"kid {kid!r} status is {key_entry.get('status')!r}")
        line = sign_line(kid, token_id, channel, env, ts)
        try:
            expected = expected_signature(key_entry["secret"], line)
        except (ValueError, KeyError):
            expected = None
        if expected is None or not hmac.compare_digest(expected, sig):
            reasons.append(REASON_BAD_SIGNATURE)
            notes.append("signature does not match canonical signing input")

    known = policy.get("known_token_ids")
    if known is not None and token_id not in known:
        reasons.append(REASON_UNKNOWN_TOKEN)
        notes.append("token_id not in policy known_token_ids")

    if channel not in (policy.get("allowed_channels") or []):
        reasons.append(REASON_CHANNEL_NOT_ALLOWED)
        notes.append(f"channel {channel!r} not in allowed set")

    if env != policy.get("env"):
        reasons.append(REASON_ENV_MISMATCH)
        notes.append(f"env {env!r} does not match policy binding")

    items = store.setdefault("items", {})
    if token_id in items:
        reasons.append(REASON_TOKEN_REPLAYED)
        notes.append("token_id already present in store")

    skew = policy.get("clock_skew_seconds")
    if skew is not None and abs(now_unix - ts) > skew:
        reasons.append(REASON_TIMESTAMP_OUT_OF_WINDOW)
        notes.append(f"ts outside +/-{skew}s window")

    if reasons:
        return _report("deny", reasons, notes)

    items[token_id] = {"ts": ts, "channel": channel, "env": env}
    return _report("allow", [], [])


def _report(decision: str, reason_codes: list[str], notes: list[str]) -> dict:
    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "kind": "canarytok",
        "notes": notes,
    }
