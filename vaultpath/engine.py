from __future__ import annotations

import base64
import hashlib
import hmac
import time
from typing import Any

_DEFAULT_GRANTED_CAPS = ("read", "write")
_DEFAULT_REQUESTED_CAPS = ("read",)


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "vaultpath", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _as_list(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [part for part in value.split(",") if part]
    if isinstance(value, (list, tuple)):
        return [str(part) for part in value]
    return [str(value)]


def _signing_line(obj: dict) -> str:
    line = obj.get("_sign_line")
    if isinstance(line, str) and line:
        return line
    caps_csv = ",".join(_as_list(obj.get("caps")))
    not_paths_csv = ",".join(_as_list(obj.get("not_paths")))
    exp = obj.get("exp", "")
    return f"v1|{obj.get('kid', '')}|{obj.get('path', '')}|{caps_csv}|{not_paths_csv}|{exp}"


def _under_prefix(path: Any, prefix: str) -> bool:
    if not isinstance(path, str) or not prefix:
        return False
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit or deny a capability-token request per docs/admit-rules.md.

    On allow the passed store is updated in place (caller persists it);
    on deny the store is left untouched.
    """
    if now_unix is None:
        now_unix = int(time.time())
    policy = policy if isinstance(policy, dict) else {}
    pkg = policy.get("pkg", "vaultpath")
    try:
        skew = int(policy.get("clock_skew_seconds", 0))
    except (TypeError, ValueError):
        skew = 0
    key_table = keys.get("keys", keys) if isinstance(keys, dict) else {}

    codes: list[str] = []
    kid = obj.get("kid")
    path = obj.get("path")
    sig = obj.get("sig")
    entry = key_table.get(kid) if isinstance(kid, str) else None

    line = _signing_line(obj)
    parts = line.split("|")
    structural_ok = len(parts) >= 3 and parts[0] == "v1" and parts[1] == kid

    if entry is None:
        codes.append("unknown_kid")
    else:
        try:
            secret = bytes.fromhex(str(entry.get("secret", "")))
            expected = _b64u(hmac.new(secret, line.encode("ascii"), hashlib.sha256).digest())
            sig_ok = structural_ok and isinstance(sig, str) and hmac.compare_digest(expected, sig)
        except (ValueError, UnicodeEncodeError):
            sig_ok = False
        if not sig_ok:
            codes.append("bad_signature")
        if entry.get("status") != "active":
            codes.append("kid_revoked")

    token_prefix = None
    granted = list(_DEFAULT_GRANTED_CAPS)
    not_paths = _as_list(obj.get("not_paths"))
    exp = obj.get("exp")
    if structural_ok and len(parts) == 6:
        token_prefix = parts[2]
        granted = _as_list(parts[3])
        not_paths = _as_list(parts[4])
        try:
            exp = int(parts[5])
        except ValueError:
            exp = None
            if "bad_signature" not in codes:
                codes.append("bad_signature")

    if exp is not None:
        try:
            if now_unix > int(exp) + skew:
                codes.append("token_expired")
        except (TypeError, ValueError):
            codes.append("token_expired")

    allowed_prefix = f"/v1/{pkg}/"
    prefix_ok = _under_prefix(path, allowed_prefix)
    if token_prefix:
        prefix_ok = prefix_ok and _under_prefix(path, token_prefix)
    if not prefix_ok:
        codes.append("path_prefix_denied")

    if any(_under_prefix(path, denied) for denied in not_paths):
        codes.append("not_path_denied")

    if "caps" in obj:
        requested = _as_list(obj.get("caps"))
        if not requested:
            codes.append("capability_empty")
    else:
        requested = list(_DEFAULT_REQUESTED_CAPS)
    if requested and not set(requested) <= set(granted):
        codes.append("capability_exceeded")

    items = store.get("items") if isinstance(store, dict) else None
    obj_id = obj.get("id")
    prior = items.get(obj_id) if isinstance(items, dict) and obj_id is not None else None
    if isinstance(prior, dict):
        prior_caps = _as_list(prior.get("caps")) or granted
        if not set(requested) <= set(prior_caps):
            codes.append("capability_widened")

    if codes:
        return {
            "decision": "deny",
            "reason_codes": codes,
            "kind": "vaultpath",
            "notes": [],
        }

    if isinstance(items, dict) and obj_id is not None:
        items[obj_id] = {"ts": now_unix, "caps": list(requested)}
    return {
        "decision": "allow",
        "reason_codes": [],
        "kind": "vaultpath",
        "notes": [],
    }
