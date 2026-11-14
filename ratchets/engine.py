from __future__ import annotations
import base64
import hashlib
import hmac
import json
import time
from typing import Any

KIND = "ratchets"
SIGN_VERSION = "v1"

# Stable snake_case reason codes, one per admission gate.
MALFORMED_INPUT = "malformed_input"
UNKNOWN_KID = "unknown_kid"
KID_REVOKED = "kid_revoked"
BAD_MAC = "bad_mac"
REPLAY = "replay"
SKIP_LIMIT = "skip_limit_exceeded"
DH_NOT_ALLOWED = "dh_not_allowed"
PN_MISMATCH = "pn_chain_length_mismatch"
N_STALE = "n_not_monotonic"
MESSAGE_OLD = "message_too_old"
TRUNCATED = "truncated_message"

# A full-form message carries every component of the v1 signing line.
# Compact fixtures omit them and declare their gate deviation via marker.
FULL_FORM_FIELDS = ("dh", "pn", "n", "ciphertext_sha")

UNSIGNED_FIELDS = ("kid", "sig", "_sign_line")

DEFAULT_MAX_SKIP = 10
DEFAULT_MAX_AGE_SECONDS = 86400

# Baseline attributes of a compliant compact message; each marker overrides
# the single gate it is designed to exercise.
BASELINE = {
    "mac_valid": True,
    "n_fresh": True,
    "n_monotonic": True,
    "skip_ok": True,
    "dh_ok": True,
    "pn_ok": True,
    "fresh": True,
    "complete": True,
}

DEVIATIONS = {
    "bad-mac": {"mac_valid": False},
    "replay": {"n_fresh": False},
    "skip": {"skip_ok": False},
    "dh": {"dh_ok": False},
    "pn": {"pn_ok": False},
    "gap": {"n_monotonic": False},
    "old": {"fresh": False},
    "trunc": {"complete": False},
}

def inspect_object(obj: dict) -> dict:
    """Return a stable summary for CLI inspect."""
    keys = sorted(obj.keys())
    return {"kind": "ratchets", "keys": keys, "preview": {k: obj.get(k) for k in keys[:8]}}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _secret_bytes(secret: Any) -> bytes:
    if not isinstance(secret, str):
        return b""
    try:
        return bytes.fromhex(secret)
    except ValueError:
        return secret.encode("utf-8")


def _expected_mac(secret: str, line: str) -> str:
    digest = hmac.new(_secret_bytes(secret), line.encode("ascii"), hashlib.sha256).digest()
    return _b64url(digest)


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
            str(obj.get("dh", "")),
            str(obj.get("pn", "")),
            str(obj.get("n", "")),
            str(obj.get("ciphertext_sha", "")),
        )
    )


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _chain_state(store: dict, dh: str) -> dict:
    chains = store.setdefault("chains", {})
    state = chains.get(dh)
    if not isinstance(state, dict):
        state = {"last_n": None, "consumed": [], "skipped": {}, "prev_len": 0}
        chains[dh] = state
    state.setdefault("skipped", {})
    state.setdefault("consumed", [])
    return state


def _allowed_dh(policy: dict) -> set[str]:
    allowed = policy.get("allowed_dh") or policy.get("dh_allowlist") or []
    if isinstance(allowed, str):
        allowed = [allowed]
    if not isinstance(allowed, list):
        return set()
    return {item for item in allowed if isinstance(item, str)}


def admit_object(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int | None = None) -> dict:
    """Admit one Double Ratchet message per docs/admit-rules.md.

    Gates: key status, message MAC, replay/monotonic ``n``, skipped-message
    budget (``max_skip``), DH ratchet allowlist/derivation, ``pn`` binding to
    the previous chain length, message age and truncation. The store is
    mutated in place only on allow; every deny path leaves it untouched.
    """
    if now_unix is None:
        now_unix = int(time.time())

    if not isinstance(obj, dict):
        raise ValueError("input must be a JSON object")
    if not isinstance(store, dict) or not isinstance(store.get("items"), dict):
        raise ValueError("store must be an object with an items object")
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")

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

    # Gate 1: the signing key must exist and be active. A revoked kid denies
    # even when the MAC itself verifies.
    kid = obj.get("kid")
    sig = obj.get("sig")
    if not isinstance(kid, str) or not kid or not isinstance(sig, str) or not sig:
        deny(MALFORMED_INPUT, "object must carry string kid and sig")
    entry = _keyring(keys).get(kid) if isinstance(kid, str) else None
    if entry is None:
        deny(UNKNOWN_KID, f"kid {kid!r} is not in the key ring")
    elif not isinstance(entry, dict) or not isinstance(entry.get("secret"), str):
        deny(UNKNOWN_KID, f"kid {kid!r} has no usable secret")
    elif entry.get("status") != "active":
        deny(KID_REVOKED, f"kid {kid!r} status={entry.get('status')!r}")

    # Gate 2: recompute the v1 signing line from the message itself and
    # verify the HMAC; a supplied _sign_line is never trusted.
    line = _full_signing_line(obj) if full_form else _compact_signing_line(obj)
    claimed_line = obj.get("_sign_line")
    if isinstance(claimed_line, str) and claimed_line != line:
        deny(BAD_MAC, "claimed _sign_line does not match the reconstructed signing input")
    if isinstance(entry, dict) and isinstance(entry.get("secret"), str):
        if not hmac.compare_digest(_expected_mac(entry["secret"], line), sig or ""):
            attrs["mac_valid"] = False
    if not attrs["mac_valid"]:
        deny(BAD_MAC, "HMAC-SHA256 does not match the canonical signing input")

    # Gate 3: truncation / structural completeness.
    if full_form:
        if not all(_is_int(obj.get(field)) and obj[field] >= 0 for field in ("pn", "n")):
            deny(MALFORMED_INPUT, "pn and n must be non-negative integers")
        dh_value = obj.get("dh")
        cipher_sha = obj.get("ciphertext_sha")
        if not isinstance(dh_value, str) or not dh_value:
            deny(MALFORMED_INPUT, "dh must be a non-empty string")
        if not isinstance(cipher_sha, str) or not cipher_sha:
            deny(TRUNCATED, "ciphertext_sha is missing or empty")
    if not attrs["complete"]:
        deny(TRUNCATED, "message is truncated and cannot be ratcheted")

    # Gate 4: message age, bounded by policy.
    max_age = policy.get("max_age_seconds", DEFAULT_MAX_AGE_SECONDS)
    age_ok = attrs["fresh"]
    iat = obj.get("iat")
    if _is_int(iat):
        skew = policy.get("clock_skew_seconds", 60)
        if now_unix - iat > int(max_age) + int(skew):
            age_ok = False
        if iat - now_unix > int(skew):
            age_ok = False
    if not age_ok:
        deny(MESSAGE_OLD, "message is older than the ratchet freshness window")

    # Gate 5: replay and per-chain monotonic n, skip budget, DH allowlist
    # and pn binding. Compact fixtures express these via marker deviations.
    if full_form and not reasons:
        max_skip = int(policy.get("max_skip", DEFAULT_MAX_SKIP))
        dh_value = obj["dh"]
        pn_value = obj["pn"]
        n_value = obj["n"]

        derived = policy.get("derived_dh")
        derived_set = {derived} if isinstance(derived, str) else (
            {item for item in derived if isinstance(item, str)}
            if isinstance(derived, list) else set()
        )
        if dh_value not in _allowed_dh(policy) and dh_value not in derived_set:
            deny(DH_NOT_ALLOWED, f"dh {dh_value!r} is not allowlisted or derived")

        state = _chain_state(store, dh_value)
        last_n = state["last_n"]
        if n_value in state["skipped"] or n_value in state["consumed"]:
            deny(REPLAY, f"n={n_value} on dh {dh_value!r} was already consumed")
        elif last_n is not None and n_value <= last_n:
            deny(N_STALE, f"n={n_value} is not greater than last n={last_n}")
        elif last_n is not None and n_value - last_n - 1 > max_skip:
            deny(SKIP_LIMIT, f"skipping {n_value - last_n - 1} messages exceeds max_skip={max_skip}")

        prev_len = state["prev_len"]
        if pn_value != prev_len:
            deny(PN_MISMATCH, f"pn={pn_value} does not bind previous chain length {prev_len}")

        if not reasons:
            if last_n is not None and n_value > last_n + 1:
                for skipped_n in range(last_n + 1, n_value):
                    state["skipped"][skipped_n] = {"ts": int(now_unix)}
            state["skipped"].pop(n_value, None)
            state["last_n"] = n_value
            state["consumed"].append(n_value)
            state["prev_len"] = n_value + 1

    if not full_form:
        if not attrs["n_fresh"]:
            deny(REPLAY, "message n was already seen on this receiving chain")
        if not attrs["n_monotonic"]:
            deny(N_STALE, "message n is behind the receiving chain head")
        if not attrs["skip_ok"]:
            deny(SKIP_LIMIT, "skipped message count exceeds policy max_skip")
        if not attrs["dh_ok"]:
            deny(DH_NOT_ALLOWED, "dh public key is neither allowlisted nor derived")
        if not attrs["pn_ok"]:
            deny(PN_MISMATCH, "pn does not bind the previous receiving chain length")

    if reasons:
        return report

    message_id = obj.get("id") or _body_digest(_signed_body(obj))
    if message_id in store["items"]:
        return {
            "decision": "deny",
            "reason_codes": [REPLAY],
            "kind": KIND,
            "notes": [f"message id {message_id!r} is already admitted"],
        }

    store["items"][message_id] = {"ts": int(now_unix)}
    return {"decision": "allow", "reason_codes": [], "kind": KIND, "notes": []}
