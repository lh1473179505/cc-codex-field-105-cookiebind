from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_caps(caps: dict) -> dict:
    return {
        "kid": caps.get("kid"),
        "permitted": list(caps.get("permitted") or []),
        "effective": list(caps.get("effective") or []),
        "bounding": list(caps.get("bounding") or []),
        "ambient": list(caps.get("ambient") or []),
        "no_new_privs": caps.get("no_new_privs"),
        "securebits": caps.get("securebits"),
    }

def _csv(items: list) -> str:
    return ",".join(items)

def _signing_line(caps: dict) -> str:
    return "v1|{kid}|{p}|{e}|{b}|{a}|{nnp}|{sb}|{nonce}".format(
        kid=caps.get("kid"),
        p=_csv(list(caps.get("permitted") or [])),
        e=_csv(list(caps.get("effective") or [])),
        b=_csv(list(caps.get("bounding") or [])),
        a=_csv(list(caps.get("ambient") or [])),
        nnp="1" if caps.get("no_new_privs") else "0",
        sb=caps.get("securebits"),
        nonce=caps.get("nonce"),
    )

def _b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def admit_caps(caps: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    permitted = list(caps.get("permitted") or [])
    effective = list(caps.get("effective") or [])
    bounding = list(caps.get("bounding") or [])
    ambient = list(caps.get("ambient") or [])
    nonce = caps.get("nonce")

    report = {"decision": "deny", "reason_codes": [], "effective": [], "ambient": []}

    # Gate 1: HMAC + kid revoke. Fail fast; contents are untrusted until signed.
    kid = caps.get("kid")
    entry = (keys.get("keys") or {}).get(kid)
    if entry is None:
        report["reason_codes"].append("unknown_kid")
        return report
    if entry.get("status") != "active":
        report["reason_codes"].append("kid_revoked")
        return report
    try:
        secret = bytes.fromhex(entry.get("secret") or "")
    except ValueError:
        secret = (entry.get("secret") or "").encode("utf-8")
    expected = _b64url_nopad(hmac.new(secret, _signing_line(caps).encode("utf-8"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, str(caps.get("sig"))):
        report["reason_codes"].append("bad_signature")
        return report

    reasons = report["reason_codes"]
    all_caps = permitted + effective + bounding + ambient

    # Gate 2: denied blacklist anywhere.
    denied = set(policy.get("denied_caps") or [])
    if any(c in denied for c in all_caps):
        reasons.append("denied_cap")

    # Gate 3: everything must be within allowed_caps.
    allowed = set(policy.get("allowed_caps") or [])
    if any(c not in allowed for c in all_caps):
        reasons.append("cap_not_allowed")

    # Gate 4: effective ⊆ permitted ⊆ bounding.
    if policy.get("require_effective_subset_permitted") and not set(effective) <= set(permitted):
        reasons.append("effective_not_subset_permitted")
    if policy.get("require_permitted_subset_bounding") and not set(permitted) <= set(bounding):
        reasons.append("permitted_not_subset_bounding")

    # Gate 5: ambient forbidden.
    if policy.get("forbid_ambient_unless_raiseable") and ambient:
        reasons.append("ambient_forbidden")

    # Gate 6: no_new_privs required.
    if policy.get("require_no_new_privs") and caps.get("no_new_privs") is not True:
        reasons.append("no_new_privs_required")

    # Gate 7: securebits exact match.
    if caps.get("securebits") not in (policy.get("allowed_securebits") or []):
        reasons.append("securebits_not_allowed")

    # Gate 8: effective size cap.
    max_effective = policy.get("max_effective")
    if max_effective is not None and len(effective) > max_effective:
        reasons.append("too_many_effective")

    # Gate 9: nonce replay; record only on allow.
    items = store.setdefault("items", {})
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return report
    items[nonce] = {"ts": now_unix}
    report["decision"] = "allow"
    report["effective"] = effective
    report["ambient"] = ambient
    return report
