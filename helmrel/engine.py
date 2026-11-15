from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_release(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "release": obj.get("release"),
        "chart": obj.get("chart"),
        "version": obj.get("version"),
        "ns": obj.get("ns"),
        "values_sha256": obj.get("values_sha256"),
        "kube": obj.get("kube"),
        "nonce": obj.get("nonce"),
    }

def _parse_semver(s: Any) -> tuple | None:
    if not isinstance(s, str):
        return None
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{release}|{chart}|{version}|{ns}|{values_sha256}|{kube}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        release=obj.get("release"),
        chart=obj.get("chart"),
        version=obj.get("version"),
        ns=obj.get("ns"),
        values_sha256=obj.get("values_sha256"),
        kube=obj.get("kube"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def admit_release(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []

    release = obj.get("release")
    name_re = policy.get("release_name_re", r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
    if not isinstance(release, str) or not re.fullmatch(name_re, release):
        reasons.append("release_name_invalid")
    if policy.get("forbid_uppercase_release") and isinstance(release, str) and release != release.lower():
        if "release_name_invalid" not in reasons:
            reasons.append("release_name_invalid")

    values_sha = obj.get("values_sha256")
    want_len = int(policy.get("values_sha256_hex_len", 64))
    if (
        not isinstance(values_sha, str)
        or len(values_sha) != want_len
        or re.fullmatch(r"[0-9a-fA-F]+", values_sha) is None
    ):
        reasons.append("values_sha256_invalid")

    charts = policy.get("charts", {})
    chart = obj.get("chart")
    chart_cfg = charts.get(chart) if isinstance(chart, str) else None
    if chart_cfg is None:
        reasons.append("chart_not_allowed")
        chart_cfg = {}

    version = obj.get("version")
    if chart_cfg and version not in chart_cfg.get("versions", []):
        reasons.append("version_not_allowed")

    ns = obj.get("ns")
    chart_ns = set(chart_cfg.get("ns", []))
    allowed_ns = set(policy.get("allowed_ns", []))
    if not isinstance(ns, str) or ns not in (chart_ns & allowed_ns):
        reasons.append("ns_not_allowed")

    kube = _parse_semver(obj.get("kube"))
    kube_min = _parse_semver(chart_cfg.get("kube_min")) if chart_cfg else None
    if kube is None or kube_min is None or kube < kube_min:
        reasons.append("kube_below_min")

    kid = obj.get("kid")
    key_entry = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        reasons.append("key_unknown")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    if key_entry is not None and key_entry.get("status") == "active":
        try:
            secret = bytes.fromhex(key_entry.get("secret", ""))
        except ValueError:
            secret = b""
        expected = hmac.new(secret, _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expected_b64, str(obj.get("sig"))):
            reasons.append("sig_invalid")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        reasons.append("iat_invalid")
    else:
        skew = int(policy.get("clock_skew_seconds", 0))
        max_age = int(policy.get("max_age_seconds", 0))
        if iat > now_unix + skew:
            reasons.append("iat_future")
        if now_unix - iat > max_age:
            reasons.append("iat_expired")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "release": release}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "release": release}
