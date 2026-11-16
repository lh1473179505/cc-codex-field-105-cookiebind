from __future__ import annotations
import base64
import hashlib
import hmac
from typing import Any
from urllib.parse import urlsplit

def inspect_chain(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "host": obj.get("host"),
        "max_age": obj.get("max_age"),
        "include_sub": obj.get("include_sub"),
        "preload": obj.get("preload"),
        "report_uri": obj.get("report_uri"),
        "ct_log": obj.get("ct_log"),
        "nonce": obj.get("nonce"),
    }

def admit_chain(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    host = obj.get("host") if isinstance(obj, dict) else None
    if not isinstance(obj, dict):
        return {"decision": "deny", "reason_codes": ["malformed"], "host": host}
    required = ("kid", "host", "max_age", "include_sub", "preload",
                "report_uri", "ct_log", "iat", "nonce", "sig")
    if any(f not in obj for f in required):
        return {"decision": "deny", "reason_codes": ["malformed"], "host": host}
    if not (isinstance(obj["host"], str)
            and isinstance(obj["max_age"], int) and not isinstance(obj["max_age"], bool)
            and obj["include_sub"] in (0, 1) and obj["preload"] in (0, 1)
            and isinstance(obj["report_uri"], str) and isinstance(obj["ct_log"], str)
            and isinstance(obj["iat"], int) and not isinstance(obj["iat"], bool)
            and isinstance(obj["nonce"], str) and isinstance(obj["kid"], str)
            and isinstance(obj["sig"], str)):
        return {"decision": "deny", "reason_codes": ["malformed"], "host": host}

    reasons: list[str] = []
    hosts = policy.get("hosts", {})

    resolved = _resolve_host(obj["host"], policy, hosts)
    cfg = hosts.get(resolved) if resolved else None
    if cfg is None:
        reasons.append("host_unknown")

    if cfg is not None:
        if obj["max_age"] < cfg.get("max_age_min", 0):
            reasons.append("max_age_below_min")
        if cfg.get("require_sub") and not obj["include_sub"]:
            reasons.append("include_sub_required")
        if not cfg.get("allow_preload") and obj["preload"]:
            reasons.append("preload_not_allowed")
        if cfg.get("require_preload_if_listed") and cfg.get("preload_listed") and not obj["preload"]:
            reasons.append("preload_required")
    if policy.get("forbid_preload_without_sub") and obj["preload"] and not obj["include_sub"]:
        reasons.append("preload_without_sub")

    try:
        url = urlsplit(obj["report_uri"])
    except ValueError:
        reasons.append("report_uri_invalid")
    else:
        if policy.get("forbid_http_report") and url.scheme != "https":
            reasons.append("report_uri_scheme")
        if policy.get("forbid_userinfo_report") and (url.username is not None or url.password is not None):
            reasons.append("report_uri_userinfo")
        if cfg is not None and (url.hostname or "") not in cfg.get("report_hosts", []):
            reasons.append("report_uri_host")
        prefix = policy.get("report_path_prefix")
        if prefix and not url.path.startswith(prefix):
            reasons.append("report_uri_path")

    if cfg is not None and obj["ct_log"] not in cfg.get("ct_logs", []):
        reasons.append("ct_log_unknown")

    key_rec = keys.get("keys", {}).get(obj["kid"])
    if key_rec is None:
        reasons.append("kid_unknown")
    elif key_rec.get("status") == "revoked":
        reasons.append("kid_revoked")
    else:
        line = "v1|{kid}|{host}|{max_age}|{include_sub}|{preload}|{report_uri}|{ct_log}|{iat}|{nonce}".format(**obj)
        digest = hmac.new(bytes.fromhex(key_rec["secret"]), line.encode("utf-8"), hashlib.sha256).digest()
        expect = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        if not hmac.compare_digest(expect, obj["sig"]):
            reasons.append("bad_signature")

    skew = policy.get("clock_skew_seconds", 0)
    window = policy.get("max_age_seconds", 0)
    if obj["iat"] > now_unix + skew:
        reasons.append("iat_future")
    elif now_unix - obj["iat"] > window:
        reasons.append("iat_stale")

    items = store.get("items") if isinstance(store, dict) else {}
    if items is not None and obj["nonce"] in items:
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "host": resolved or obj["host"]}
    if items is None:
        items = {}
        store["items"] = items
    items[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "host": resolved}


def _resolve_host(host: str, policy: dict, hosts: dict) -> str | None:
    h = host
    if policy.get("host_normalize_strip_dot") and h.endswith("."):
        h = h[:-1]
    if h in hosts:
        return h
    if policy.get("host_normalize_www") and h.startswith("www.") and h[4:] in hosts:
        return h[4:]
    for name, cfg in hosts.items():
        aliases = cfg.get("aliases", [])
        if h in aliases or host in aliases:
            return name
    return None
