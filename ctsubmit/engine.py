from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any

TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


def _deny(log_id: Any, code: str) -> dict:
    return {"decision": "deny", "reason_codes": [code], "log_id": log_id}


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not TIMESTAMP_RE.match(value):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _signing_input(obj: dict) -> str | None:
    chain = obj.get("chain")
    if not isinstance(chain, list) or not all(isinstance(cert, str) for cert in chain):
        return None
    parts = [
        "v1",
        obj.get("kid"),
        obj.get("log_id"),
        ",".join(chain),
        obj.get("root_sha256"),
        obj.get("not_before"),
        obj.get("not_after"),
        obj.get("hostname"),
        obj.get("iat"),
        obj.get("nonce"),
    ]
    if any(not isinstance(part, str) for part in parts[1:8]) or not isinstance(parts[8], int) \
            or not isinstance(parts[9], str):
        return None
    parts[8] = str(parts[8])
    return "|".join(parts)


def _signature_valid(obj: dict, secret_hex: str) -> bool:
    message = _signing_input(obj)
    submitted = obj.get("sig")
    if message is None or not isinstance(submitted, str):
        return False
    try:
        secret = bytes.fromhex(secret_hex)
    except ValueError:
        return False
    digest = hmac.new(secret, message.encode("utf-8"), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return hmac.compare_digest(expected, submitted)


def _chain_code(chain: Any, log: dict) -> str:
    if not isinstance(chain, list) or not all(isinstance(cert, str) for cert in chain):
        return "chain_missing"
    for allowed in log.get("chains", []):
        if chain == allowed:
            return ""
    wanted = Counter(chain) if isinstance(chain, list) else Counter()
    for allowed in log.get("chains", []):
        if Counter(allowed) == wanted:
            return "chain_order"
    return "chain_missing"


def _hostname_valid(hostname: Any, log: dict) -> bool:
    if not isinstance(hostname, str) or not hostname:
        return False
    labels = hostname.split(".")
    if any(not LABEL_RE.match(label) for label in labels):
        return False
    for suffix in log.get("hostname_suffixes", []):
        if not isinstance(suffix, str) or not suffix.startswith("."):
            continue
        if hostname.endswith(suffix) and len(hostname) > len(suffix):
            return True
    return False


def inspect_submission(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "log_id": obj.get("log_id"),
        "chain": obj.get("chain"),
        "root_sha256": obj.get("root_sha256"),
        "not_before": obj.get("not_before"),
        "not_after": obj.get("not_after"),
        "hostname": obj.get("hostname"),
        "nonce": obj.get("nonce"),
    }


def admit_submission(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    log_id = obj.get("log_id")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if not isinstance(key_entry, dict):
        return _deny(log_id, "unknown_kid")
    if not _signature_valid(obj, key_entry.get("secret", "")):
        return _deny(log_id, "bad_signature")
    if key_entry.get("status") != "active":
        return _deny(log_id, "key_revoked")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        return _deny(log_id, "iat_invalid")
    if iat - now_unix > policy.get("clock_skew_seconds", 60):
        return _deny(log_id, "iat_future")
    if now_unix - iat > policy.get("max_age_seconds", 600):
        return _deny(log_id, "iat_expired")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        return _deny(log_id, "bad_nonce")
    if nonce in store.get("items", {}):
        return _deny(log_id, "replay")

    log = policy.get("logs", {}).get(log_id)
    if not isinstance(log, dict):
        return _deny(log_id, "unknown_log")

    chain_code = _chain_code(obj.get("chain"), log)
    if chain_code:
        return _deny(log_id, chain_code)

    root = obj.get("root_sha256")
    root_length = policy.get("root_hex_length", 64)
    lowercase_required = policy.get("require_lowercase_root", True)
    root_pattern = r"^[0-9a-f]{%d}$" % root_length if lowercase_required \
        else r"^[0-9a-fA-F]{%d}$" % root_length
    if not isinstance(root, str) or not re.match(root_pattern, root):
        return _deny(log_id, "root_format")
    if not hmac.compare_digest(root, log.get("root_sha256", "")):
        return _deny(log_id, "root_mismatch")

    not_before = _parse_timestamp(obj.get("not_before"))
    not_after = _parse_timestamp(obj.get("not_after"))
    if not_before is None or not_after is None:
        return _deny(log_id, "bad_timestamp")
    min_bound = _parse_timestamp(log.get("not_before_min"))
    max_bound = _parse_timestamp(log.get("not_after_max"))
    if min_bound is not None and not_before < min_bound:
        return _deny(log_id, "not_before_early")
    if max_bound is not None and not_after > max_bound:
        return _deny(log_id, "not_after_late")
    if not_after <= not_before:
        return _deny(log_id, "not_after_not_later")
    if (not_after - not_before).total_seconds() > log.get("max_validity_seconds", 0):
        return _deny(log_id, "validity_too_long")

    if not _hostname_valid(obj.get("hostname"), log):
        return _deny(log_id, "host_suffix")

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "log_id": log_id}
