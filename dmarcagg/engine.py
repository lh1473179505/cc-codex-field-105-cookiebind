from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
import re
from typing import Any

def inspect_report(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "org": obj.get("org"),
        "domain": obj.get("domain"),
        "report_id": obj.get("report_id"),
        "begin": obj.get("begin"),
        "end": obj.get("end"),
        "records": obj.get("records"),
        "total_count": obj.get("total_count"),
        "report_sha256": obj.get("report_sha256"),
        "nonce": obj.get("nonce"),
    }

_COUNT_RE = re.compile(r"[1-9][0-9]*")
_HEX_RE = re.compile(r"[0-9a-f]+")

def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)

def _expected_sig(secret_hex: str, obj: dict) -> str:
    msg = "|".join([
        "v1",
        obj["kid"],
        obj["org"],
        obj["domain"],
        obj["report_id"],
        str(obj["begin"]),
        str(obj["end"]),
        ",".join(obj["records"]),
        str(obj["total_count"]),
        obj["report_sha256"],
        str(obj["iat"]),
        obj["nonce"],
    ])
    digest = hmac.new(bytes.fromhex(secret_hex), msg.encode("ascii"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_report(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []
    report_id = obj.get("report_id") if isinstance(obj.get("report_id"), str) else None

    # structural type checks
    str_fields = ["org", "domain", "report_id", "report_sha256", "nonce", "kid", "sig"]
    if any(not isinstance(obj.get(f), str) or not obj.get(f) for f in str_fields):
        codes.append("malformed_field")
    if not _is_int(obj.get("begin")) or not _is_int(obj.get("end")):
        codes.append("malformed_range")
    if not _is_int(obj.get("total_count")):
        codes.append("malformed_total_count")
    if not _is_int(obj.get("iat")):
        codes.append("malformed_iat")
    records = obj.get("records")
    if not isinstance(records, list) or any(not isinstance(r, str) for r in records):
        codes.append("malformed_records")
        records = []
    if codes:
        return {"decision": "deny", "reason_codes": codes, "report_id": report_id}

    # domain / org / report_id binding
    dom = policy.get("domains", {}).get(obj["domain"])
    if dom is None:
        codes.append("domain_not_allowed")
        dom = {}
    if dom and obj["org"] not in dom.get("orgs", []):
        codes.append("org_not_allowed")
    if dom:
        prefixes = dom.get("report_id_prefixes", [])
        if not any(obj["report_id"].startswith(p) and len(obj["report_id"]) > len(p) for p in prefixes):
            codes.append("report_id_not_allowed")

    # range: strict order and exact window
    begin, end = obj["begin"], obj["end"]
    if not begin < end:
        codes.append("range_order")
    elif dom and end - begin != dom.get("window_seconds"):
        codes.append("range_duration")

    # records
    if not (policy.get("record_min", 0) <= len(records) <= policy.get("record_max", 1 << 30)):
        codes.append("record_count_bounds")
    networks = [ipaddress.ip_network(c) for c in dom.get("source_cidrs", [])]
    spf_ok = set(policy.get("spf_results", []))
    dkim_ok = set(policy.get("dkim_results", []))
    seen_sources: set[str] = set()
    total = 0
    for rec in records:
        parts = rec.split("|")
        if len(parts) != 4 or any(not p.isascii() for p in parts):
            codes.append("record_format")
            continue
        source_ip, count_s, spf, dkim = parts
        try:
            addr = ipaddress.ip_address(source_ip)
        except ValueError:
            codes.append("record_format")
            continue
        if dom and not any(addr in net for net in networks):
            codes.append("source_cidr")
        if policy.get("require_unique_source"):
            if source_ip in seen_sources:
                codes.append("source_not_unique")
            seen_sources.add(source_ip)
        if not _COUNT_RE.fullmatch(count_s):
            codes.append("record_count_format")
        else:
            total += int(count_s)
        if spf not in spf_ok:
            codes.append("spf_result")
        if dkim not in dkim_ok:
            codes.append("dkim_result")
        if policy.get("require_any_aligned") and spf != "pass" and dkim != "pass":
            codes.append("no_alignment")

    # total_count cross-check
    if _is_int(obj["total_count"]) and obj["total_count"] != total:
        codes.append("count_mismatch")

    # digest shape
    digest = obj["report_sha256"]
    if len(digest) != policy.get("report_sha256_hex_len", 64) or not _HEX_RE.fullmatch(digest):
        codes.append("report_sha256_format")
    elif policy.get("require_lowercase_hex") and digest != digest.lower():
        codes.append("report_sha256_format")

    # key status
    key = keys.get("keys", {}).get(obj["kid"])
    if key is None:
        codes.append("unknown_kid")
    elif key.get("status") != "active":
        codes.append("key_revoked")

    # signature
    if key is not None and not hmac.compare_digest(_expected_sig(key["secret"], obj), obj["sig"]):
        codes.append("bad_signature")

    # iat skew / freshness
    iat = obj["iat"]
    if iat > now_unix + policy.get("clock_skew_seconds", 0):
        codes.append("iat_future")
    if now_unix - iat > policy.get("max_age_seconds", 0):
        codes.append("iat_stale")

    # nonce replay
    items = store.setdefault("items", {})
    if obj["nonce"] in items:
        codes.append("replay")

    if codes:
        return {"decision": "deny", "reason_codes": sorted(set(codes)), "report_id": report_id}
    items[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "report_id": report_id}
