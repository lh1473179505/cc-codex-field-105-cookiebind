from __future__ import annotations
import base64
import hashlib
import hmac

SIGNING_VERSION = "v1"
_REQUIRED_FIELDS = (
    "kid", "d", "s", "from_domain", "arc_cv",
    "body_hash", "iat", "nonce", "sig",
)

def inspect_mail(mail: dict) -> dict:
    return {"kid": mail.get("kid"), "d": mail.get("d"), "s": mail.get("s"), "from_domain": mail.get("from_domain"), "arc_cv": mail.get("arc_cv"), "nonce": mail.get("nonce")}


def _signing_input(mail: dict) -> bytes:
    parts = (
        SIGNING_VERSION,
        mail["kid"],
        mail["d"],
        mail["s"],
        mail["from_domain"],
        mail["arc_cv"],
        mail["body_hash"],
        mail["iat"],
        mail["nonce"],
    )
    return "|".join(str(part) for part in parts).encode("utf-8")


def _expected_signature(secret_hex: str, signing_input: bytes) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), signing_input, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def admit_mail(mail: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    missing = [name for name in _REQUIRED_FIELDS if mail.get(name) is None]
    if missing:
        raise ValueError("mail missing field: " + ",".join(missing))
    if not isinstance(mail["iat"], int) or isinstance(mail["iat"], bool):
        raise ValueError("mail iat must be an integer unix timestamp")

    reasons: list[str] = []

    entry = keys.get("keys", {}).get(mail["kid"])
    if entry is None:
        reasons.append("unknown_kid")
    else:
        if entry.get("status") == "revoked":
            reasons.append("kid_revoked")
        try:
            expected = _expected_signature(entry.get("secret", ""), _signing_input(mail))
        except ValueError:
            reasons.append("bad_signature")
        else:
            provided = mail["sig"]
            if not isinstance(provided, str) or not hmac.compare_digest(expected, provided):
                reasons.append("bad_signature")

    if mail["d"] not in policy.get("allowed_d", []):
        reasons.append("d_not_allowed")
    if mail["s"] not in policy.get("allowed_s", []):
        reasons.append("selector_not_allowed")

    if policy.get("from_must_align_d") and mail["from_domain"] != mail["d"]:
        reasons.append("from_not_aligned")

    if mail["arc_cv"] not in policy.get("required_arc_cv", []):
        reasons.append("arc_cv_not_allowed")

    age = int(now_unix) - mail["iat"]
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if age < -skew or age > max_age:
        reasons.append("iat_outside_window")

    items = store.setdefault("items", {})
    if mail["nonce"] in items:
        reasons.append("nonce_replayed")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "d": mail.get("d")}

    items[mail["nonce"]] = {"ts": int(now_unix)}
    return {"decision": "allow", "reason_codes": [], "d": mail.get("d")}
