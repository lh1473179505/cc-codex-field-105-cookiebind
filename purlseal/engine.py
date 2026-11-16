from __future__ import annotations
import base64
import hashlib
import hmac
import re

CANONICAL_VERSION = "v1"
_REQUIRED_FIELDS = (
    "kid", "purl", "registry", "name", "version",
    "digest", "license", "iat", "nonce", "sig",
)
_STRING_FIELDS = (
    "kid", "purl", "registry", "name", "version",
    "digest", "license", "nonce", "sig",
)

def inspect_pkg(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "purl": obj.get("purl"),
        "registry": obj.get("registry"),
        "name": obj.get("name"),
        "version": obj.get("version"),
        "digest": obj.get("digest"),
        "license": obj.get("license"),
        "nonce": obj.get("nonce"),
    }


def admit_pkg(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    name = obj.get("name")

    missing = [f for f in _REQUIRED_FIELDS if obj.get(f) is None]
    bad_types = [f for f in _STRING_FIELDS if not isinstance(obj.get(f), str)]
    iat = obj.get("iat")
    if missing or bad_types or not isinstance(iat, int) or isinstance(iat, bool):
        return {"decision": "deny", "reason_codes": ["malformed_input"], "name": name}

    kid = obj["kid"]
    purl = obj["purl"]
    registry = obj["registry"]
    version = obj["version"]
    digest = obj["digest"]
    license_id = obj["license"]
    nonce = obj["nonce"]
    sig = obj["sig"]

    reasons: list[str] = []

    matched_type = next(
        (t for t in policy.get("allowed_types", []) if purl.startswith(t + "/")),
        None,
    )
    if matched_type is None:
        reasons.append("bad_purl_type")

    if f"/{name}@{version}" not in purl:
        reasons.append("purl_binding_mismatch")

    uppercase = False
    if policy.get("require_lowercase_name") and name != name.lower():
        uppercase = True
    if policy.get("forbid_uppercase_in_purl") and purl != purl.lower():
        uppercase = True
    if uppercase:
        reasons.append("uppercase_name")

    if registry not in policy.get("allowed_registries", []):
        reasons.append("registry_not_allowed")

    if name in policy.get("denied_names", []):
        reasons.append("name_denied")

    if license_id not in policy.get("allowed_licenses", []):
        reasons.append("license_not_allowed")

    digest_alg = policy.get("digest_alg", "sha256")
    digest_pattern = re.escape(digest_alg) + r":[0-9a-f]{64}"
    if re.fullmatch(digest_pattern, digest) is None:
        reasons.append("bad_digest")

    key_entry = keys.get("keys", {}).get(kid)
    if key_entry is None:
        reasons.append("unknown_kid")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")
    else:
        canonical = "|".join((
            CANONICAL_VERSION, kid, purl, registry, name, version,
            digest, license_id, str(iat), nonce,
        ))
        secret = bytes.fromhex(key_entry["secret"])
        mac = hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).digest()
        expected_sig = base64.urlsafe_b64encode(mac).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected_sig, sig):
            reasons.append("bad_signature")

    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if iat > now_unix + skew or iat < now_unix - max_age:
        reasons.append("iat_out_of_window")

    if nonce in store.get("items", {}):
        reasons.append("nonce_replayed")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "name": name}

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "name": name}
