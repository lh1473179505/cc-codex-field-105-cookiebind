from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
SIG_INVALID = "sig_invalid"
SHARE_DENIED = "share_denied"
USER_GROUP_DENIED = "user_group_denied"
GROUP_SHARE_DENIED = "group_share_denied"
UNC_TRAVERSAL_DENIED = "unc_traversal_denied"
UNC_SERVER_DENIED = "unc_server_denied"
UNC_SHARE_DENIED = "unc_share_denied"
UNC_FOLDER_DENIED = "unc_folder_denied"
SIGNING_DENIED = "signing_denied"
ENCRYPTION_DENIED = "encryption_denied"
DIALECT_DENIED = "dialect_denied"
IAT_OUT_OF_WINDOW = "iat_out_of_window"
REPLAY = "replay"

# Every claim participates in the HMAC, in the declared signing order.
_SIGN_VERSION = "v1"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hmac_b64url(secret_hex: str, line: str) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex), line.encode("ascii"), hashlib.sha256
    ).digest()
    return _b64url(digest)


def _signing_line(obj: dict) -> str:
    # Booleans render as True/False and iat as a decimal int; the engine
    # always recomputes the line from the ticket itself.
    return "|".join(
        [
            _SIGN_VERSION,
            str(obj.get("kid")),
            str(obj.get("user")),
            str(obj.get("group")),
            str(obj.get("share")),
            str(obj.get("unc_path")),
            str(obj.get("signing")),
            str(obj.get("encryption")),
            str(obj.get("dialect")),
            str(obj.get("iat")),
            str(obj.get("nonce")),
        ]
    )


def _keyring(keys: Any) -> dict:
    ring = keys.get("keys") if isinstance(keys, dict) else None
    return ring if isinstance(ring, dict) else (keys if isinstance(keys, dict) else {})


def _unc_gate(path: Any, share: dict, policy: dict) -> str | None:
    """Validate the UNC namespace against the selected share.

    Structural violations (empty components, "."/"..", forward slashes,
    NUL, encoded separators, policy deny substrings) fail before any
    server/share/folder boundary check so a traversal cannot hide behind
    a lookalike prefix.
    """
    if not isinstance(path, str):
        return UNC_TRAVERSAL_DENIED

    for denied in policy.get("unc_deny_substrings", []) or []:
        if isinstance(denied, str) and denied in path:
            return UNC_TRAVERSAL_DENIED

    if (
        "\x00" in path
        or "/" in path
        or "%" in path
        or not path.startswith("\\\\")
    ):
        return UNC_TRAVERSAL_DENIED

    parts = path.split("\\")
    # Leading "\\" yields two empty components; every later component
    # must be a real, non-dot segment.
    if any(component == "" for component in parts[2:]):
        return UNC_TRAVERSAL_DENIED
    if any(component in (".", "..") for component in parts):
        return UNC_TRAVERSAL_DENIED
    if len(parts) < 5:
        return UNC_TRAVERSAL_DENIED

    root = share.get("unc_root")
    if not isinstance(root, str):
        return UNC_SHARE_DENIED
    root_parts = root.split("\\")
    if len(root_parts) != 4 or root_parts[0] != "" or root_parts[1] != "":
        return UNC_SHARE_DENIED
    expected_server, expected_share_name = root_parts[2], root_parts[3]

    server, share_name = parts[2], parts[3]
    if server != expected_server or server != share.get("server"):
        return UNC_SERVER_DENIED
    if share_name != expected_share_name:
        return UNC_SHARE_DENIED

    expected_prefix = root + "\\"
    if not path.startswith(expected_prefix):
        return UNC_SHARE_DENIED
    remainder = path[len(expected_prefix):]
    folder_prefixes = share.get("folder_prefixes") or []
    if not any(
        isinstance(prefix, str) and remainder.startswith(prefix)
        for prefix in folder_prefixes
    ):
        return UNC_FOLDER_DENIED
    return None


def inspect_access(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "user": obj.get("user"),
        "group": obj.get("group"),
        "share": obj.get("share"),
        "unc_path": obj.get("unc_path"),
        "signing": obj.get("signing"),
        "encryption": obj.get("encryption"),
        "dialect": obj.get("dialect"),
        "nonce": obj.get("nonce"),
    }

def admit_access(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    report = {"decision": "deny", "reason_codes": [], "share": obj.get("share")}
    reasons = report["reason_codes"]

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    # Gate 1: the signing key must exist and be active. A revoked or
    # unknown kid denies even when the HMAC itself would verify.
    ring = _keyring(keys)
    entry = ring.get(obj.get("kid"))
    active_entry = (
        entry if isinstance(entry, dict) and entry.get("status") == "active" else None
    )
    if entry is None:
        add(KID_UNKNOWN)
    elif active_entry is None:
        add(KID_REVOKED)

    # Gate 2: recompute the v1 signing line from the ticket itself and
    # verify the HMAC over every field in declared order.
    if active_entry is not None:
        secret = active_entry.get("secret")
        try:
            expected = _hmac_b64url(secret, _signing_line(obj))
        except (TypeError, ValueError):
            expected = ""
        if not hmac.compare_digest(expected, obj.get("sig") or ""):
            add(SIG_INVALID)

    shares = policy.get("shares") if isinstance(policy, dict) else None
    shares = shares if isinstance(shares, dict) else {}
    share = shares.get(obj.get("share"))
    share_known = isinstance(share, dict)

    # Gate 3: the selected share must exist in policy. Authorization on
    # another share is irrelevant.
    if not share_known:
        add(SHARE_DENIED)

    # Gate 4: user must be an exact member of the ticket's global group.
    groups = policy.get("groups") if isinstance(policy, dict) else None
    groups = groups if isinstance(groups, dict) else {}
    group = groups.get(obj.get("group"))
    members = group.get("users") if isinstance(group, dict) else None
    if not (isinstance(members, list) and obj.get("user") in members):
        add(USER_GROUP_DENIED)

    # Gate 5: that group must be one of the selected share's groups.
    if share_known and obj.get("group") not in (share.get("groups") or []):
        add(GROUP_SHARE_DENIED)

    if share_known:
        # Gate 6: UNC server, share name and folder prefix are bound to
        # the selected share, with traversal/prefix attacks rejected.
        unc_reason = _unc_gate(obj.get("unc_path"), share, policy)
        if unc_reason is not None:
            add(unc_reason)

        # Gate 7: negotiated signing/encryption/dialect must match the
        # share's own requirements exactly.
        if obj.get("signing") is not share.get("signing"):
            add(SIGNING_DENIED)
        if obj.get("encryption") is not share.get("encryption"):
            add(ENCRYPTION_DENIED)
        if obj.get("dialect") not in (share.get("dialects") or []):
            add(DIALECT_DENIED)

    # Gate 8: iat must sit inside the clock-skew / max-age window.
    skew = policy.get("clock_skew_seconds", 60) if isinstance(policy, dict) else 60
    max_age = policy.get("max_age_seconds", 600) if isinstance(policy, dict) else 600
    iat = obj.get("iat")
    if (
        not isinstance(iat, int)
        or isinstance(iat, bool)
        or iat - now_unix > skew
        or now_unix - iat > max_age
    ):
        add(IAT_OUT_OF_WINDOW)

    # Gate 9: replay protection. A nonce may be consumed once and only
    # an allow may record it; a deny never touches the store.
    items = store.get("items") if isinstance(store, dict) else None
    if isinstance(items, dict) and obj.get("nonce") in items:
        add(REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[obj.get("nonce")] = {"ts": int(now_unix)}
    return report
