from __future__ import annotations

import base64
import hashlib
import hmac
import os
from typing import Any

# Stable snake_case reason codes, in canonical report order.
_GATE_ORDER = [
    "unknown_kid",
    "kid_revoked",
    "bad_sig",
    "key_mismatch",
    "exe_not_absolute",
    "exe_mismatch",
    "success_mismatch",
    "uid_mismatch",
    "uid_out_of_range",
    "replay",
]

_DEFAULT_UID_MIN = 0
_DEFAULT_UID_MAX = 65535


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "auditmatch", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _secret_bytes(entry: dict) -> bytes:
    secret = str(entry.get("secret", ""))
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def _bool_text(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _sign_line(obj: dict) -> str:
    """Signed line: explicit ``_sign_line`` or reconstructed per docs/admit-rules.md."""
    line = obj.get("_sign_line")
    if isinstance(line, str) and line:
        return line
    exe = obj.get("exe", obj.get("path", ""))
    parts = [
        "v1",
        str(obj.get("kid", "")),
        str(obj.get("key", "")),
        str(exe),
        _bool_text(obj.get("success", "")),
        str(obj.get("uid", "")),
    ]
    return "|".join(parts)


def _parse_sign_line(line: str) -> dict | None:
    fields = line.split("|")
    if len(fields) < 3 or fields[0] != "v1":
        return None
    claimed = {"kid": fields[1], "key": fields[2]}
    if len(fields) >= 6:
        claimed["exe"] = fields[3]
        claimed["success"] = fields[4]
        claimed["uid"] = fields[5]
    return claimed


def _exe_allowed(norm_exe: str, policy: dict) -> bool:
    """Normalized real path must match the policy allow list."""
    allow = policy.get("exe_allow") or policy.get("allowed_exe")
    if isinstance(allow, str):
        allow = [allow]
    prefixes = policy.get("exe_allow_prefixes") or policy.get("allowed_exe_prefixes")
    if isinstance(prefixes, str):
        prefixes = [prefixes]
    if allow is None and prefixes is None:
        pkg = policy.get("pkg")
        prefixes = [f"/v1/{pkg}"] if pkg else []
    for exact in allow or []:
        if norm_exe == os.path.realpath(str(exact)):
            return True
    for prefix in prefixes or []:
        norm_prefix = os.path.realpath(str(prefix))
        if norm_exe == norm_prefix or norm_exe.startswith(norm_prefix.rstrip("/") + "/"):
            return True
    return False


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate the admit gates from docs/admit-rules.md.

    Returns the report dict from docs/report-schema.md. On ``allow`` the
    event id is recorded into ``store`` (mutated in place); on ``deny`` the
    store is left untouched.
    """
    if not isinstance(obj, dict):
        raise ValueError("input object must be a JSON object")
    keys = keys if isinstance(keys, dict) else {}
    policy = policy if isinstance(policy, dict) else {}
    store = store if isinstance(store, dict) else {"items": {}}
    items = store.setdefault("items", {})
    if not isinstance(items, dict):
        raise ValueError("store must be object with items object")

    reasons: set[str] = set()
    notes: list[str] = []

    keyring = keys.get("keys", keys)
    if not isinstance(keyring, dict):
        keyring = {}
    kid = obj.get("kid")
    entry = keyring.get(kid) if isinstance(kid, str) else None
    secret = None
    if entry is None:
        reasons.add("unknown_kid")
        notes.append(f"kid {kid!r} is not in the keyring")
    else:
        if entry.get("status") != "active":
            reasons.add("kid_revoked")
            notes.append(f"kid {kid!r} is revoked")
        secret = _secret_bytes(entry)

    line = _sign_line(obj)
    claimed = _parse_sign_line(line)
    if claimed is None:
        reasons.add("bad_sig")
        notes.append("sign line is malformed")
    elif claimed["kid"] != str(kid):
        reasons.add("bad_sig")
        notes.append("sign line kid does not match the presented kid")

    if secret is not None:
        expected_sig = _b64url_nopad(hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest())
        if not hmac.compare_digest(expected_sig, str(obj.get("sig", ""))):
            reasons.add("bad_sig")
            notes.append("HMAC-SHA256 signature does not match the sign line")

    # key gate: exact, case-sensitive, no normalization.
    if claimed is not None:
        obj_key = obj.get("key")
        if obj_key is not None and str(obj_key) != claimed["key"]:
            reasons.add("key_mismatch")
            notes.append("object key does not exactly match the signed key")
        expected_key = policy.get("expected_key")
        if expected_key is None and isinstance(entry, dict):
            expected_key = entry.get("key")
        if expected_key is not None and claimed["key"] != str(expected_key):
            reasons.add("key_mismatch")
            notes.append("signed key does not match the policy key")

    # exe gate: normalized real path must match the policy allow list.
    exe = obj.get("exe", obj.get("path"))
    norm_exe = None
    if not isinstance(exe, str) or not exe:
        reasons.add("exe_mismatch")
        notes.append("object carries no exe path")
    else:
        if not os.path.isabs(exe):
            reasons.add("exe_not_absolute")
            notes.append(f"exe path {exe!r} is not absolute")
        norm_exe = os.path.realpath(exe)
        if not _exe_allowed(norm_exe, policy):
            reasons.add("exe_mismatch")
            notes.append(f"normalized exe {norm_exe!r} is not allowed by policy")
    if claimed is not None and "exe" in claimed and norm_exe is not None:
        if os.path.realpath(claimed["exe"]) != norm_exe:
            reasons.add("exe_mismatch")
            notes.append("signed exe does not match the object exe")

    # success gate: boolean must agree with the signed line and the policy.
    if "success" in obj:
        success = obj["success"]
        if not isinstance(success, bool):
            reasons.add("success_mismatch")
            notes.append("success is not a boolean")
        else:
            if claimed is not None and "success" in claimed and claimed["success"] != _bool_text(success):
                reasons.add("success_mismatch")
                notes.append("signed success does not match the object success")
            expected_success = policy.get("expected_success")
            if expected_success is not None and success != bool(expected_success):
                reasons.add("success_mismatch")
                notes.append("success does not match the policy expectation")

    # uid gate: integer inside the policy range, consistent with the line.
    if "uid" in obj:
        uid = obj["uid"]
        if isinstance(uid, bool) or not isinstance(uid, int):
            reasons.add("uid_out_of_range")
            notes.append("uid is not an integer")
        else:
            uid_min = int(policy.get("uid_min", _DEFAULT_UID_MIN))
            uid_max = int(policy.get("uid_max", _DEFAULT_UID_MAX))
            if not (uid_min <= uid <= uid_max):
                reasons.add("uid_out_of_range")
                notes.append(f"uid {uid} outside [{uid_min}, {uid_max}]")
            if claimed is not None and "uid" in claimed and claimed["uid"] != str(uid):
                reasons.add("uid_mismatch")
                notes.append("signed uid does not match the object uid")

    # replay gate: an id already recorded in the store is not admitted again.
    event_id = obj.get("id", obj.get("sig"))
    if event_id is not None and str(event_id) in items:
        reasons.add("replay")
        notes.append(f"event id {event_id!r} was already admitted")

    ordered = [code for code in _GATE_ORDER if code in reasons]
    if ordered:
        return {
            "decision": "deny",
            "reason_codes": ordered,
            "kind": str(policy.get("pkg", "auditmatch")),
            "notes": notes,
        }

    if event_id is not None:
        items[str(event_id)] = {"ts": now_unix if now_unix is not None else 0}
    return {
        "decision": "allow",
        "reason_codes": [],
        "kind": str(policy.get("pkg", "auditmatch")),
        "notes": [],
    }
