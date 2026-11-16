from __future__ import annotations
import base64
import hashlib
import hmac

SIGNING_LINE = (
    "v1|{kid}|{key_fp}|{signer_fp}|{depth}|{algo}|{hash}|"
    "{notation}|{notation_val}|{body_sha256}|{iat}|{nonce}"
)

SIGNING_FIELDS = (
    "kid",
    "key_fp",
    "signer_fp",
    "depth",
    "algo",
    "hash",
    "notation",
    "notation_val",
    "body_sha256",
    "iat",
    "nonce",
)

def inspect_sig(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "key_fp": obj.get("key_fp"),
        "signer_fp": obj.get("signer_fp"),
        "depth": obj.get("depth"),
        "algo": obj.get("algo"),
        "hash": obj.get("hash"),
        "notation": obj.get("notation"),
        "nonce": obj.get("nonce"),
    }

def admit_sig(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    key_fp = obj.get("key_fp")
    reasons: list[str] = []

    if not all(field in obj for field in SIGNING_FIELDS) or "sig" not in obj:
        return {
            "decision": "deny",
            "reason_codes": ["malformed_sig"],
            "key_fp": key_fp,
        }

    key_entries = keys.get("keys", {})
    key = key_entries.get(obj["kid"])
    if key is None:
        reasons.append("unknown_kid")

    if key is not None and key.get("status") != "active":
        reasons.append("key_revoked")

    # HMAC binding: the signature covers every field of the signing line,
    # so a tampered leaf fingerprint, signer, depth, notation value or body
    # digest cannot be validated against a separately trusted policy.
    expected_mac = ""
    if key is not None:
        try:
            secret = bytes.fromhex(str(key.get("secret", "")))
            line = SIGNING_LINE.format(**obj)
            expected_mac = base64.urlsafe_b64encode(
                hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest()
            ).rstrip(b"=").decode("ascii")
        except (ValueError, TypeError):
            expected_mac = ""
    if not expected_mac or not hmac.compare_digest(expected_mac, str(obj["sig"])):
        reasons.append("bad_sig")

    leaf = policy.get("fps", {}).get(obj["key_fp"])
    if leaf is None:
        reasons.append("unknown_key_fp")

    if leaf is not None:
        # Trust path: signer must be an authorized signer for this leaf AND
        # a trusted root anchor. Both memberships are required, which blocks
        # cross-domain CA signatures and unanchored signers.
        if obj["signer_fp"] not in leaf.get("signers", []):
            reasons.append("signer_not_authorized")
        if obj["signer_fp"] not in policy.get("trusted_roots", []):
            reasons.append("signer_not_trusted_root")

        depth = obj["depth"]
        if not isinstance(depth, int) or isinstance(depth, bool) or not (
            1 <= depth <= leaf.get("max_depth", 0)
        ):
            reasons.append("depth_exceeded")

        if obj["algo"] not in leaf.get("algos", []):
            reasons.append("algo_not_allowed")

        if obj["hash"] not in leaf.get("hashes", []):
            reasons.append("hash_not_allowed")
        if leaf.get("forbid_md5") and obj["hash"] == "md5":
            reasons.append("md5_forbidden")

        # Critical notation: exact name, exact policy-URI value, and the
        # deny-substring filter (e.g. javascript:) applied to the value.
        notation = obj["notation"]
        notation_val = obj["notation_val"]
        if notation not in leaf.get("required_notations", []):
            reasons.append("notation_not_required")
        elif leaf.get("notation_values", {}).get(notation) != notation_val:
            reasons.append("notation_value_mismatch")
        for denied in policy.get("notation_deny_substrings", []):
            if isinstance(notation_val, str) and denied in notation_val:
                reasons.append("notation_value_forbidden")
                break

    body_sha256 = obj["body_sha256"]
    if not isinstance(body_sha256, str) or len(body_sha256) != policy.get("body_sha256_len", 64):
        reasons.append("body_sha256_bad_length")

    iat = obj["iat"]
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("iat_invalid")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat - now_unix > skew:
            reasons.append("sig_in_future")
        if now_unix - iat > max_age + skew:
            reasons.append("sig_expired")

    nonce = obj["nonce"]
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replayed")

    if reasons:
        return {
            "decision": "deny",
            "reason_codes": reasons,
            "key_fp": key_fp,
        }

    # Allow-only nonce store: mutated solely when every check passed.
    store.setdefault("items", {})[nonce] = {"ts": iat}
    return {
        "decision": "allow",
        "reason_codes": [],
        "key_fp": key_fp,
    }
