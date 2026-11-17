from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re
from typing import Any

# Stable snake_case reason codes, one per admission gate.
KID_UNKNOWN = "kid_unknown"
KID_REVOKED = "kid_revoked"
SIG_INVALID = "sig_invalid"
NAS_UNKNOWN = "nas_unknown"
USER_UNKNOWN = "user_unknown"
SESSION_PREFIX_DENIED = "session_prefix_denied"
SESSION_SYNTAX_DENIED = "session_syntax_denied"
ACCT_SESSION_PREFIX_DENIED = "acct_session_prefix_denied"
ATTRIBUTE_REQUIRED_DENIED = "attribute_required_denied"
ATTRIBUTE_EXTRA_DENIED = "attribute_extra_denied"
ATTRIBUTE_VALUE_DENIED = "attribute_value_denied"
SOURCE_SYNTAX_DENIED = "source_syntax_denied"
SOURCE_CIDR_DENIED = "source_cidr_denied"
IAT_WINDOW_DENIED = "iat_window_denied"
REPLAY = "replay"

# session_id / acct_session_id: lowercase ASCII letters, digits and hyphens.
SESSION_TOKEN_RE = re.compile(r"[a-z0-9-]+\Z")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _hmac_b64url(secret_hex: str, line: str) -> str:
    key = bytes.fromhex(secret_hex)
    digest = hmac.new(key, line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


def _session_token_ok(value: Any) -> bool:
    return isinstance(value, str) and SESSION_TOKEN_RE.fullmatch(value) is not None


def _canonical_attributes(attributes: Any) -> str:
    # Attribute keys are sorted and rendered as comma-separated key=value
    # items. Non-object inputs canonicalize to the empty form.
    if not isinstance(attributes, dict):
        return ""
    return ",".join(f"{key}={attributes[key]}" for key in sorted(attributes))


def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{nas_id}|{session_id}|{acct_session_id}|{username}|{attributes}|{source_ip}|{iat}|{nonce}".format(
        kid=obj.get("kid", ""),
        nas_id=obj.get("nas_id", ""),
        session_id=obj.get("session_id", ""),
        acct_session_id=obj.get("acct_session_id", ""),
        username=obj.get("username", ""),
        attributes=_canonical_attributes(obj.get("attributes")),
        source_ip=obj.get("source_ip", ""),
        iat=obj.get("iat", ""),
        nonce=obj.get("nonce", ""),
    )


def inspect_coa(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "nas_id": obj.get("nas_id"),
        "session_id": obj.get("session_id"),
        "acct_session_id": obj.get("acct_session_id"),
        "username": obj.get("username"),
        "attributes": obj.get("attributes"),
        "source_ip": obj.get("source_ip"),
        "nonce": obj.get("nonce"),
    }


def admit_coa(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    """Evaluate a RADIUS CoA request against policy per docs/admit-rules.md.

    Returns the report described in docs/report-schema.md. The nonce is
    recorded in ``store`` only when the decision is allow; a deny never
    mutates the store.
    """
    report = {"decision": "deny", "reason_codes": [], "session_id": obj.get("session_id")}
    reasons = report["reason_codes"]

    def add(code: str) -> None:
        if code not in reasons:
            reasons.append(code)

    devices = policy.get("nas_devices", {})
    nas_id = obj.get("nas_id")
    nas = devices.get(nas_id) if isinstance(devices, dict) else None
    if not isinstance(nas, dict):
        add(NAS_UNKNOWN)
        nas = None

    user = None
    if nas is not None:
        users = nas.get("users", {})
        username = obj.get("username")
        user = users.get(username) if isinstance(users, dict) else None
        if not isinstance(user, dict):
            add(USER_UNKNOWN)
            user = None

    # session_id: syntax first, then a prefix bound to the selected NAS.
    session_id = obj.get("session_id")
    if not _session_token_ok(session_id):
        add(SESSION_SYNTAX_DENIED)
    elif nas is not None and not any(
        isinstance(prefix, str) and session_id.startswith(prefix)
        for prefix in nas.get("session_prefixes", [])
    ):
        add(SESSION_PREFIX_DENIED)

    # acct_session_id: same syntax, and a prefix bound to the NAS/user pair.
    acct_session_id = obj.get("acct_session_id")
    if not _session_token_ok(acct_session_id):
        add(SESSION_SYNTAX_DENIED)
    elif user is not None and not any(
        isinstance(prefix, str) and acct_session_id.startswith(prefix)
        for prefix in user.get("acct_session_prefixes", [])
    ):
        add(ACCT_SESSION_PREFIX_DENIED)

    # attributes: allowed key set, required exact values, per-key values.
    attributes = obj.get("attributes")
    if not isinstance(attributes, dict) or not all(
        isinstance(value, str) for value in attributes.values()
    ):
        add(ATTRIBUTE_REQUIRED_DENIED)
        add(ATTRIBUTE_EXTRA_DENIED)
        add(ATTRIBUTE_VALUE_DENIED)
    elif user is not None:
        allowed = set(user.get("attributes_allowed", []))
        supplied = set(attributes)
        required = user.get("attributes_required", {})
        values = user.get("attribute_values", {})

        if any(key not in allowed for key in supplied):
            add(ATTRIBUTE_EXTRA_DENIED)

        if any(
            key not in attributes or attributes.get(key) != required[key]
            for key in required
        ):
            add(ATTRIBUTE_REQUIRED_DENIED)

        known = supplied & allowed
        if any(
            attributes[key] not in values.get(key, [])
            for key in known
        ):
            add(ATTRIBUTE_VALUE_DENIED)

    # source_ip: parse as an IP address, then require a NAS source_cidrs match.
    source_ip = obj.get("source_ip")
    try:
        parsed_ip = ipaddress.ip_address(source_ip) if isinstance(source_ip, str) else None
    except ValueError:
        parsed_ip = None
    if parsed_ip is None:
        add(SOURCE_SYNTAX_DENIED)
    elif nas is not None and not any(
        parsed_ip in ipaddress.ip_network(cidr)
        for cidr in nas.get("source_cidrs", [])
    ):
        add(SOURCE_CIDR_DENIED)

    # iat: stale beyond max_age or future beyond clock_skew are denied.
    iat = obj.get("iat")
    skew = policy.get("clock_skew_seconds", 60)
    max_age = policy.get("max_age_seconds", 600)
    if (
        not isinstance(iat, int)
        or isinstance(iat, bool)
        or iat > now_unix + skew
        or iat < now_unix - max_age
    ):
        add(IAT_WINDOW_DENIED)

    # Key gates: the kid must exist and be active; a revoked kid denies even
    # when the HMAC itself verifies.
    keyring = keys.get("keys") if isinstance(keys, dict) else None
    entry = keyring.get(obj.get("kid")) if isinstance(keyring, dict) else None
    active_entry = entry if isinstance(entry, dict) and entry.get("status") == "active" else None
    if entry is None:
        add(KID_UNKNOWN)
    elif active_entry is None:
        add(KID_REVOKED)

    if active_entry is not None:
        secret = active_entry.get("secret")
        supplied_sig = obj.get("sig")
        if not isinstance(secret, str) or not isinstance(supplied_sig, str):
            add(SIG_INVALID)
        else:
            try:
                expected_sig = _hmac_b64url(secret, _signing_line(obj))
            except ValueError:
                expected_sig = ""
            if not hmac.compare_digest(expected_sig, supplied_sig):
                add(SIG_INVALID)

    # Replay protection: the nonce may be consumed only once, and only an
    # allow may record it. Any denial leaves the store untouched.
    nonce = obj.get("nonce")
    items = store.get("items") if isinstance(store, dict) else None
    if not isinstance(nonce, str) or not nonce or (isinstance(items, dict) and nonce in items):
        add(REPLAY)

    if reasons:
        return report

    report["decision"] = "allow"
    store.setdefault("items", {})[nonce] = {"ts": int(now_unix)}
    return report
