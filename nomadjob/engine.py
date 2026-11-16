from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any

def inspect_job(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "job": obj.get("job"),
        "driver": obj.get("driver"),
        "network": obj.get("network"),
        "volume": obj.get("volume"),
        "image": obj.get("image"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{job}|{driver}|{network}|{volume}|{image}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        job=obj.get("job"),
        driver=obj.get("driver"),
        network=obj.get("network"),
        volume=obj.get("volume"),
        image=obj.get("image"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def admit_job(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    job = obj.get("job")
    jobs = policy.get("jobs", {})
    spec = jobs.get(job)
    if spec is None:
        reasons.append("job_not_allowed")
        spec = {}
    if obj.get("driver") not in spec.get("drivers", []):
        reasons.append("driver_not_allowed")
    network = obj.get("network")
    if network not in spec.get("networks", []):
        reasons.append("network_not_allowed")
    volume = obj.get("volume")
    if not isinstance(volume, str) or not any(
        volume.startswith(p) for p in spec.get("volume_prefixes", [])
    ):
        reasons.append("volume_prefix_not_allowed")
    elif any(d in volume for d in policy.get("volume_deny_substrings", [])):
        reasons.append("volume_denied_substring")
    image = obj.get("image")
    if not isinstance(image, str) or not any(
        image.startswith(p) for p in spec.get("image_prefixes", [])
    ):
        reasons.append("image_prefix_not_allowed")
    if network in policy.get("forbid_privileged_network_for", {}).get(job, []):
        reasons.append("privileged_network_forbidden")

    kid = obj.get("kid")
    key = keys.get("keys", {}).get(kid)
    if key is None:
        reasons.append("key_unknown")
    elif key.get("status") != "active":
        reasons.append("key_revoked")
    else:
        expected = hmac.new(
            bytes.fromhex(key["secret"]),
            _signing_line(obj).encode("utf-8"),
            hashlib.sha256,
        ).digest()
        try:
            provided = _b64url_decode(str(obj.get("sig", "")))
        except Exception:
            provided = b""
        if not hmac.compare_digest(expected, provided):
            reasons.append("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat > now_unix + skew:
            reasons.append("iat_in_future")
        elif now_unix - iat > max_age:
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "job": job}
    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "job": job}
