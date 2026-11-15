from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_answer(answer: dict) -> dict:
    return {
        "kid": answer.get("kid"),
        "signer": answer.get("signer"),
        "type_covered": answer.get("type_covered"),
        "names": sorted({rr.get("name") for rr in (answer.get("rrset") or [])}),
        "inception": answer.get("inception"),
        "expiration": answer.get("expiration"),
        "nonce": answer.get("nonce"),
    }

def _canonical_rrset(rrset: list) -> str:
    ordered = sorted(rrset, key=lambda rr: str(rr.get("rdata", "")))
    return "\n".join(
        "|".join((
            str(rr.get("name", "")),
            str(rr.get("type", "")),
            str(rr.get("class", "")),
            str(rr.get("ttl", "")),
            str(rr.get("rdata", "")),
        ))
        for rr in ordered
    )

def _cover(answer: dict) -> str:
    canonical = _canonical_rrset(answer.get("rrset") or [])
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

def _signing_line(answer: dict, cover: str) -> str:
    return "|".join((
        "v1",
        str(answer.get("kid", "")),
        str(answer.get("signer", "")),
        str(answer.get("type_covered", "")),
        str(answer.get("labels", "")),
        str(answer.get("orig_ttl", "")),
        str(answer.get("inception", "")),
        str(answer.get("expiration", "")),
        cover,
        str(answer.get("nonce", "")),
    ))

def _expected_sig(answer: dict, secret_hex: str, cover: str) -> str:
    mac = hmac.new(
        bytes.fromhex(secret_hex),
        _signing_line(answer, cover).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")

def _dns_name_key(name: str) -> tuple:
    labels = [label.encode("utf-8") for label in str(name).split(".") if label]
    labels.reverse()
    return tuple(labels)

def _nsec_interval_covers(owner: str, next_name: str, claim: str) -> bool:
    owner_key = _dns_name_key(owner)
    next_key = _dns_name_key(next_name)
    claim_key = _dns_name_key(claim)
    if owner_key == next_key:
        return False
    if owner_key < next_key:
        return owner_key < claim_key < next_key
    return claim_key > owner_key or claim_key < next_key

def _deny(answer: dict, code: str) -> dict:
    return {
        "decision": "deny",
        "reason_codes": [code],
        "signer": answer.get("signer"),
        "type_covered": answer.get("type_covered"),
    }

def admit_answer(answer: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    cover = _cover(answer)

    key_records = keys.get("keys") or {}
    key = key_records.get(answer.get("kid"))
    if key is None:
        return _deny(answer, "unknown_kid")
    if key.get("status") != "active":
        return _deny(answer, "key_revoked")
    if "signer" in key and key.get("signer") != answer.get("signer"):
        return _deny(answer, "signer_mismatch")
    expected = _expected_sig(answer, key.get("secret", ""), cover)
    if not hmac.compare_digest(expected, str(answer.get("sig", ""))):
        return _deny(answer, "bad_signature")

    if answer.get("signer") not in (policy.get("allowed_signers") or []):
        return _deny(answer, "signer_not_allowed")
    type_covered = answer.get("type_covered")
    if type_covered not in (policy.get("allowed_types") or []):
        return _deny(answer, "type_not_allowed")
    rrset = answer.get("rrset") or []
    if policy.get("require_uniform_name_type") and any(
        rr.get("type") != type_covered for rr in rrset
    ):
        return _deny(answer, "mixed_type")

    suffix = policy.get("require_rrset_name_suffix", "")
    names = [str(rr.get("name", "")) for rr in rrset]
    if any(not name.endswith(suffix) for name in names):
        return _deny(answer, "name_suffix")
    if policy.get("require_uniform_name_type") and len(set(names)) > 1:
        return _deny(answer, "non_uniform_name")

    skew = int(policy.get("clock_skew_seconds", 0))
    if now_unix < int(answer.get("inception", 0)) - skew:
        return _deny(answer, "not_yet_valid")
    if now_unix > int(answer.get("expiration", 0)):
        return _deny(answer, "expired")

    if int(answer.get("labels", 0)) > int(policy.get("max_labels", 0)):
        return _deny(answer, "labels_exceeded")

    nsec = answer.get("nsec")
    if isinstance(nsec, dict) and nsec.get("claims_nxdomain_for"):
        claim = nsec.get("claims_nxdomain_for")
        covered = _nsec_interval_covers(nsec.get("owner", ""), nsec.get("next", ""), claim)
        claim_absent = claim not in set(names)
        if not covered or not claim_absent:
            return _deny(answer, "nsec_lie")

    nonce = answer.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        return _deny(answer, "nonce_replay")

    items[nonce] = {"ts": now_unix}
    return {
        "decision": "allow",
        "reason_codes": [],
        "signer": answer.get("signer"),
        "type_covered": type_covered,
    }
