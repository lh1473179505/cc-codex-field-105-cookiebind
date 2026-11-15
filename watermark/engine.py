from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

PAYLOAD_FIELDS = ("case", "id", "marker", "path")
REQUIRED_FIELDS = ("case", "id", "marker", "path", "kid", "sig")
DEFAULT_ALLOWED_POS_PREFIXES = ("/v1/watermark/",)
DEFAULT_SCORE_THRESHOLD = 1.0


def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "watermark", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _canonical_payload(obj: dict) -> bytes:
    payload = {k: obj[k] for k in PAYLOAD_FIELDS}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign_line(obj: dict) -> str:
    digest = hashlib.sha256(_canonical_payload(obj)).hexdigest()
    return f"v1|{obj['kid']}|{digest}"


def _expected_sig(secret_hex: str, line: str) -> str:
    mac = hmac.new(bytes.fromhex(secret_hex), line.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Evaluate all admit gates from docs/admit-rules.md.

    Returns the report dict. On "allow" the admission is recorded into
    ``store`` (mutated in place); on "deny" the store is left untouched.
    Raises ValueError on malformed inputs (load failure).
    """
    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(keys, dict) or not isinstance(keys.get("keys"), dict):
        raise ValueError("keys must be an object with a keys object")
    if not isinstance(policy, dict):
        raise ValueError("policy must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be an object with an items object")

    reasons: list[str] = []

    missing = [f for f in REQUIRED_FIELDS if not isinstance(obj.get(f), str) or not obj.get(f)]
    if missing:
        return {
            "decision": "deny",
            "reason_codes": ["missing_fields"],
            "kind": policy.get("pkg", "watermark"),
            "notes": ["missing or empty fields: " + ",".join(missing)],
        }

    keyring = keys["keys"]
    entry = keyring.get(obj["kid"])
    if entry is None:
        reasons.append("unknown_key")
    elif entry.get("status") != "active":
        reasons.append("key_revoked")

    prefixes = policy.get("allowed_pos_prefixes", DEFAULT_ALLOWED_POS_PREFIXES)
    if not any(obj["path"].startswith(p) for p in prefixes):
        reasons.append("pos_not_allowed")

    line = _sign_line(obj)
    provided_line = obj.get("_sign_line")
    if provided_line is not None and provided_line != line:
        reasons.append("mark_mismatch")

    threshold = float(policy.get("score_threshold", DEFAULT_SCORE_THRESHOLD))
    score = 0.0
    if isinstance(entry, dict):
        secret = entry.get("secret")
        if isinstance(secret, str):
            try:
                expected = _expected_sig(secret, line)
            except ValueError:
                expected = None
            if expected is not None:
                if hmac.compare_digest(expected, obj["sig"]):
                    score = 1.0
                else:
                    reasons.append("bad_signature")
    if score < threshold:
        reasons.append("score_below_threshold")

    decision = "allow" if not reasons else "deny"
    if decision == "allow":
        store["items"][str(obj["id"])] = {"ts": now_unix}

    return {
        "decision": decision,
        "reason_codes": reasons,
        "kind": policy.get("pkg", "watermark"),
        "notes": [f"score={score:.2f}", f"threshold={threshold:.2f}"],
    }
