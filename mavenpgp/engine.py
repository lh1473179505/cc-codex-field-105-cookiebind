from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_art(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "group": obj.get("group"),
        "artifact": obj.get("artifact"),
        "version": obj.get("version"),
        "fp": obj.get("fp"),
        "nonce": obj.get("nonce"),
    }

def _sign_line(obj: dict) -> str:
    return "v1|{kid}|{group}|{artifact}|{version}|{fp}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        group=obj.get("group"),
        artifact=obj.get("artifact"),
        version=obj.get("version"),
        fp=obj.get("fp"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_art(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    group = obj.get("group")
    artifact = obj.get("artifact")
    version = obj.get("version")
    fp = obj.get("fp")
    nonce = obj.get("nonce")
    iat = obj.get("iat")
    kid = obj.get("kid")

    coord = f"{group}:{artifact}"
    coords = policy.get("coords", {})
    entry = coords.get(coord)
    if entry is None:
        reasons.append("coord_not_allowed")
    else:
        prefixes = entry.get("version_prefixes", [])
        if not isinstance(version, str) or not any(version.startswith(p) for p in prefixes):
            reasons.append("version_prefix_mismatch")
        if fp not in entry.get("fps", []):
            reasons.append("fp_not_allowed")

    if policy.get("forbid_snapshot") and isinstance(version, str) and version.endswith("-SNAPSHOT"):
        reasons.append("snapshot_forbidden")

    key = keys.get("keys", {}).get(kid)
    if key is None:
        reasons.append("unknown_key")
    else:
        if key.get("status") != "active":
            reasons.append("key_revoked")
        expected = _expected_sig(key.get("secret", ""), _sign_line(obj))
        if not hmac.compare_digest(expected, str(obj.get("sig"))):
            reasons.append("bad_sig")

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if not isinstance(iat, int) or iat > now_unix + skew or iat < now_unix - max_age:
        reasons.append("iat_out_of_window")

    items = store.get("items", {})
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "artifact": artifact}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "artifact": artifact}
