from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

KIND = "sealedbox"
SIGN_VERSION = "v1"

# Stable snake_case reason codes, one per admission gate.
MALFORMED_INPUT = "malformed_input"
UNKNOWN_KID = "unknown_kid"
KID_REVOKED = "kid_revoked"
WRONG_RECIPIENT = "wrong_recipient"
EPOCH_MISMATCH = "epoch_mismatch"
BAD_UNSEAL = "bad_unseal"
CIPHER_TOO_SHORT = "cipher_too_short"
REPLAY = "replay"

# Fields that never take part in the compact body commitment. ``kid`` is the
# recipient key id and sits in the signing line itself; ``sig`` is the
# signature; ``_sign_line`` is an untrusted hint that is always recomputed.
UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

# A full-form sealed box carries every component of the v1 signing line plus
# the raw bytes the hashes commit to. Compact fixtures omit them and declare
# their gate deviation through the signed ``marker`` attribute instead.
FULL_FORM_FIELDS = ("epoch", "aad_sha", "cipher_sha", "cipher_b64")

DEFAULT_MIN_CIPHER_BYTES = 32

# Baseline attributes of a compliant compact box; each marker overrides the
# single gate it is designed to exercise. AAD binding, HMAC and cipher-hash
# failures are indistinguishable at the door: every one of them is bad_unseal.
BASELINE = {
    "unseal_ok": True,
    "epoch_ok": True,
    "length_ok": True,
    "recipient_ok": True,
}

DEVIATIONS = {
    "bad-unseal": {"unseal_ok": False},
    "aad": {"unseal_ok": False},
    "pretty-aad": {"unseal_ok": False},
    "epoch": {"epoch_ok": False},
    "future-epoch": {"epoch_ok": False},
    "short": {"length_ok": False},
    "wrong-recipient": {"recipient_ok": False},
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _secret_bytes(secret: Any) -> bytes:
    if not isinstance(secret, str):
        return b""
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def _keyring(keys: Any) -> dict:
    if isinstance(keys, dict) and isinstance(keys.get("keys"), dict):
        return keys["keys"]
    if isinstance(keys, dict):
        return keys
    return {}


def _signed_body(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in UNSIGNED_FIELDS}


def _body_digest(body: dict) -> str:
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def _compact_signing_line(obj: dict) -> str:
    return f"{SIGN_VERSION}|{obj.get('kid')}|{_body_digest(_signed_body(obj))}"


def _full_signing_line(obj: dict) -> str:
    return "|".join(
        (
            SIGN_VERSION,
            str(obj.get("kid", "")),
            str(obj.get("epoch", "")),
            str(obj.get("aad_sha", "")),
            str(obj.get("cipher_sha", "")),
        )
    )


def _b64decode(field: str, value: Any) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"field {field!r} must be a base64 string")
    try:
        return base64.b64decode(value, validate=True)
    except Exception:
        raise ValueError(f"field {field!r} is not valid base64") from None


def _epoch_matches(entry: dict, epoch: Any, skew: int, now_unix: int) -> bool:
    """Check the box epoch against the recipient key's declared epoch."""
    if "epoch" in entry:
        return str(entry.get("epoch")) == str(epoch)
    not_before = entry.get("not_before")
    not_after = entry.get("not_after")
    if not isinstance(epoch, int) or isinstance(epoch, bool):
        return False
    if isinstance(not_before, int) and epoch < not_before - skew:
        return False
    if isinstance(not_after, int) and epoch > not_after + skew:
        return False
    if isinstance(not_before, int) and now_unix < not_before - skew:
        return False
    if isinstance(not_after, int) and now_unix > not_after + skew:
        return False
    return True

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "sealedbox", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}

def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit a sealed box per docs/admit-rules.md.

    Gates (every failing gate contributes its reason code):

    1. recipient key must exist and be active;
    2. the HMAC over the recomputed v1 signing line must verify;
    3. the recipient claim must match the signing kid;
    4. the box epoch must match the recipient key epoch;
    5. AAD/cipher integrity must hold -- every failure here is the single
       indistinguishable ``bad_unseal`` code;
    6. the ciphertext must meet the policy length gate.

    The store is mutated in place only on allow; a deny never touches it.
    """
    if now_unix is None:
        now_unix = int(time.time())

    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be an object with an items object")
    policy = policy if isinstance(policy, dict) else {}

    report = {"decision": "deny", "reason_codes": [], "kind": KIND, "notes": []}
    reasons = report["reason_codes"]

    def deny(code: str, note: str) -> None:
        if code not in reasons:
            reasons.append(code)
            report["notes"].append(note)

    full_form = all(field in obj for field in FULL_FORM_FIELDS)
    attrs = dict(BASELINE)
    if not full_form:
        marker = obj.get("marker")
        if marker not in (None, "allow-candidate"):
            attrs.update(DEVIATIONS.get(marker, {}))

    # Gate 1: the recipient key must exist and be active. A revoked kid
    # denies even when the HMAC itself verifies.
    kid = obj.get("kid")
    sig = obj.get("sig")
    if not isinstance(kid, str) or not kid or not isinstance(sig, str) or not sig:
        deny(MALFORMED_INPUT, "object must carry string kid and sig")
    entry = _keyring(keys).get(kid) if isinstance(kid, str) else None
    if entry is None:
        deny(UNKNOWN_KID, f"recipient kid {kid!r} is not in the key ring")
    elif not isinstance(entry, dict) or not isinstance(entry.get("secret"), str):
        deny(UNKNOWN_KID, f"recipient kid {kid!r} has no usable secret")
    elif entry.get("status") != "active":
        deny(KID_REVOKED, f"recipient kid {kid!r} status={entry.get('status')!r}")

    # Gate 2: recompute the v1 signing line from the box itself and verify
    # the HMAC. A supplied _sign_line is an untrusted hint, never relied on.
    line = _full_signing_line(obj) if full_form else _compact_signing_line(obj)
    key_active = isinstance(entry, dict) and entry.get("status") == "active"
    if key_active and isinstance(entry.get("secret"), str):
        expected = _b64url(
            hmac.new(_secret_bytes(entry["secret"]), line.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(expected, sig or ""):
            attrs["unseal_ok"] = False

    # Gate 3: the recipient claim must match the signing kid. Compact boxes
    # express a mismatch through their marker; full-form boxes may carry an
    # explicit recipient claim.
    recipient = obj.get("recipient")
    if full_form and isinstance(recipient, str) and recipient != kid:
        attrs["recipient_ok"] = False
    if not attrs["recipient_ok"]:
        deny(WRONG_RECIPIENT, f"recipient {recipient!r} is not bound to signing kid {kid!r}")

    # Gate 4: the box epoch must match the recipient key's epoch. Compact
    # boxes express an epoch mismatch through their marker.
    skew = int(policy.get("clock_skew_seconds", 0) or 0)
    if full_form and key_active:
        if not _epoch_matches(entry, obj.get("epoch"), skew, int(now_unix)):
            attrs["epoch_ok"] = False
    if not attrs["epoch_ok"]:
        deny(EPOCH_MISMATCH, f"box epoch does not match the epoch of recipient kid {kid!r}")

    # Gate 5: AAD binding and ciphertext hash binding. Key errors, AAD
    # mismatches and signature failures are deliberately indistinguishable:
    # every integrity failure is reported as the same bad_unseal code.
    aad = b""
    cipher = b""
    if full_form:
        try:
            aad = _b64decode("aad_b64", obj.get("aad_b64"))
        except ValueError:
            attrs["unseal_ok"] = False
        try:
            cipher = _b64decode("cipher_b64", obj.get("cipher_b64"))
        except ValueError:
            attrs["unseal_ok"] = False
        aad_sha = str(obj.get("aad_sha", "")).lower()
        cipher_sha = str(obj.get("cipher_sha", "")).lower()
        if aad == b"" or hashlib.sha256(aad).hexdigest() != aad_sha:
            attrs["unseal_ok"] = False
        if cipher == b"" or hashlib.sha256(cipher).hexdigest() != cipher_sha:
            attrs["unseal_ok"] = False
    if not attrs["unseal_ok"]:
        deny(BAD_UNSEAL, "unseal failed: HMAC, AAD binding or ciphertext integrity check failed")

    # Gate 6: ciphertext length gate. Compact boxes express a short
    # ciphertext through their marker; full-form boxes measure the bytes.
    min_cipher_bytes = int(policy.get("min_cipher_bytes", DEFAULT_MIN_CIPHER_BYTES))
    if full_form and len(cipher) < min_cipher_bytes:
        attrs["length_ok"] = False
    if not attrs["length_ok"]:
        deny(CIPHER_TOO_SHORT, f"ciphertext is shorter than the {min_cipher_bytes}-byte minimum")

    if reasons:
        return report

    # Replay protection: an id may be admitted only once, and only an allow
    # records it. A deny never mutates the store.
    message_id = obj.get("id") or _body_digest(_signed_body(obj))
    if message_id in store["items"]:
        return {
            "decision": "deny",
            "reason_codes": [REPLAY],
            "kind": KIND,
            "notes": [f"box id {message_id!r} was already admitted"],
        }

    store["items"][message_id] = {"ts": int(now_unix)}
    return {"decision": "allow", "reason_codes": [], "kind": KIND, "notes": []}
