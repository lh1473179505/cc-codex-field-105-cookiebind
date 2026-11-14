from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any
from urllib.parse import urlparse

def inspect_plan(plan: dict) -> dict:
    u = urlparse(plan.get("url") or "")
    return {
        "method": plan.get("method"),
        "scheme": u.scheme,
        "host": u.hostname,
        "path": u.path,
        "kid": plan.get("kid"),
        "pin_ips": list(plan.get("pin_ips") or []),
        "redirects": list(plan.get("redirects") or []),
    }

def _sign_line(kid, method, url, body_sha256, authority_host, pin_ips) -> str:
    return "|".join([
        "v1", kid or "", method or "", url or "", body_sha256 or "",
        authority_host or "", ",".join(pin_ips or []),
    ])

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _split_authority(url: str):
    """Return (scheme, authority) from the raw URL without normalizing it."""
    scheme = ""
    rest = url
    if "://" in url:
        scheme, rest = url.split("://", 1)
    authority = rest
    for sep in ("/", "?", "#"):
        idx = authority.find(sep)
        if idx != -1:
            authority = authority[:idx]
    return scheme, authority

def _looks_like_ipv4(host: str) -> bool:
    """inet_aton-style detection: dotted-decimal, integer, hex, octal forms."""
    if not host:
        return False
    parts = host.split(".")
    if len(parts) > 4 or any(p == "" for p in parts):
        return False
    values = []
    for part in parts:
        try:
            if part.lower().startswith("0x"):
                value = int(part, 16)
            elif len(part) > 1 and part.startswith("0"):
                value = int(part, 8)
            else:
                if not part.isdigit():
                    return False
                value = int(part, 10)
        except ValueError:
            return False
        values.append(value)
    if len(values) == 1:
        return 0 <= values[0] <= 0xFFFFFFFF
    for value in values[:-1]:
        if not 0 <= value <= 0xFF:
            return False
    return 0 <= values[-1] < (1 << (8 * (5 - len(values))))

def _normalize_host(raw_host: str) -> str:
    host = raw_host or ""
    if host.endswith("."):
        host = host[:-1]
    return host.lower() if host.isascii() else host

def _check_url_gates(url, authority_host, pin_ips, resolver, policy):
    """Run offline authority gates on raw strings. Returns (host, ips, reason_codes)."""
    reasons = []
    scheme, authority = _split_authority(url or "")
    if scheme not in (policy.get("allowed_schemes") or []):
        reasons.append("scheme_not_allowed")
    if policy.get("forbid_http_backslash") and "\\" in authority:
        reasons.append("bad_authority")
    if policy.get("forbid_userinfo") and "@" in authority:
        reasons.append("userinfo_forbidden")
    if reasons:
        return None, [], reasons

    raw_host = authority_host if authority_host is not None else authority.rsplit("@", 1)[-1].split(":", 1)[0]
    host = _normalize_host(raw_host)

    if not host.isascii() and policy.get("idna_policy") == "prefer_punycode_label":
        return host, [], ["idna_required"]
    if policy.get("forbid_decimal_ipv4_obfuscation") and _looks_like_ipv4(host):
        return host, [], ["ipv4_obfuscation"]

    allow = {str(e.get("exact", "")).lower() for e in (policy.get("host_allow") or [])}
    if host not in allow:
        return host, [], ["host_not_allowed"]

    ips = list((resolver or {}).get(host) or [])
    if not ips:
        return host, [], ["nxdomain"]

    if policy.get("require_dns_pin_match", True):
        pinned = set(pin_ips or [])
        if any(ip not in pinned for ip in ips):
            reasons.append("pin_mismatch")
    blocked = [ipaddress.ip_network(c) for c in (policy.get("blocked_cidrs") or [])]
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if any(addr in net for net in blocked):
            reasons.append("blocked_ip")
            break
    return host, ips, reasons

def admit_plan(plan: dict, keys: dict, policy: dict, now_unix: int | None = None) -> dict:
    def deny(reasons, host=None, ips=None):
        return {"decision": "deny", "reason_codes": list(reasons), "host": host, "ips": list(ips or [])}

    kid = plan.get("kid")
    keyrec = (keys.get("keys") or {}).get(kid)
    if keyrec is None:
        return deny(["unknown_kid"])
    if keyrec.get("status") != "active":
        return deny(["kid_revoked"])

    line = _sign_line(kid, plan.get("method"), plan.get("url"), plan.get("body_sha256"),
                      plan.get("authority_host"), plan.get("pin_ips"))
    expected = _expected_sig(keyrec.get("secret") or "", line)
    if not hmac.compare_digest(expected, str(plan.get("sig") or "")):
        return deny(["bad_signature"])

    skew = int(policy.get("clock_skew_seconds") or 0)
    if now_unix is not None:
        if plan.get("not_before") is not None and now_unix + skew < int(plan["not_before"]):
            return deny(["not_yet_valid"])
        if plan.get("expires_at") is not None and now_unix - skew > int(plan["expires_at"]):
            return deny(["expired"])

    if plan.get("method") not in (policy.get("allowed_methods") or []):
        return deny(["method_not_allowed"])

    host, ips, reasons = _check_url_gates(
        plan.get("url"), plan.get("authority_host"), plan.get("pin_ips"),
        plan.get("resolver"), policy)
    if reasons:
        return deny(reasons, host, ips)

    redirects = list(plan.get("redirects") or [])
    max_redirects = int(policy.get("max_redirects") or 0)
    if len(redirects) > max_redirects:
        return deny(["too_many_redirects"], host, ips)
    for redirect in redirects:
        if isinstance(redirect, dict):
            r_url, r_host = redirect.get("url"), redirect.get("authority_host")
            r_pins, r_resolver = redirect.get("pin_ips"), redirect.get("resolver")
        else:
            r_url, r_host, r_pins, r_resolver = redirect, None, None, None
        _, _, r_reasons = _check_url_gates(
            r_url, r_host, r_pins if r_pins is not None else plan.get("pin_ips"),
            r_resolver if r_resolver is not None else plan.get("resolver"), policy)
        if r_reasons:
            return deny(r_reasons, host, ips)

    return {"decision": "allow", "reason_codes": [], "host": host, "ips": ips}
