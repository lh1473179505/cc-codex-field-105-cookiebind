from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

def inspect_update(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "zone": obj.get("zone"),
        "owner": obj.get("owner"),
        "rrtype": obj.get("rrtype"),
        "operation": obj.get("operation"),
        "rdata": obj.get("rdata"),
        "ttl": obj.get("ttl"),
        "prerequisites": obj.get("prerequisites"),
        "nonce": obj.get("nonce"),
    }

def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)

def _hmac_line(obj: dict) -> str:
    rdata = ",".join(obj["rdata"])
    prereq = ",".join(f"{k}={obj['prerequisites'][k]}" for k in sorted(obj["prerequisites"]))
    return (
        f"v1|{obj['kid']}|{obj['zone']}|{obj['owner']}|{obj['rrtype']}|"
        f"{obj['operation']}|{rdata}|{obj['ttl']}|{prereq}|{obj['iat']}|{obj['nonce']}"
    )

def _sig_valid(secret_hex: str, obj: dict) -> bool:
    try:
        secret = bytes.fromhex(secret_hex)
        line = _hmac_line(obj)
    except (ValueError, KeyError, TypeError):
        return False
    digest = hmac.new(secret, line.encode("utf-8"), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return hmac.compare_digest(expected, str(obj["sig"]))

def admit_update(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []
    owner = obj.get("owner")

    zones = policy.get("zones", {})
    key_map = keys.get("keys", {})

    key = key_map.get(obj.get("kid"))
    if key is None:
        codes.append("unknown_key")
    elif key.get("status") != "active":
        codes.append("key_revoked")

    sig = obj.get("sig")
    if key is not None and key.get("status") == "active":
        if not isinstance(sig, str) or not _sig_valid(str(key.get("secret", "")), obj):
            codes.append("bad_sig")

    zone = zones.get(obj.get("zone"))
    if zone is None:
        codes.append("unknown_zone")

    if not isinstance(owner, str):
        codes.append("owner_invalid")
    else:
        if policy.get("require_lowercase_owner") and owner != owner.lower():
            codes.append("owner_not_lowercase")
        if policy.get("require_absolute_owner") and not owner.endswith("."):
            codes.append("owner_not_absolute")
        if ".." in owner or owner.startswith("."):
            codes.append("owner_empty_label")
        if zone is not None:
            zname = obj.get("zone")
            if not (isinstance(zname, str) and owner != zname and owner.endswith("." + zname)):
                codes.append("owner_out_of_zone")

    rrspec = None
    if zone is not None:
        rrspec = zone.get("rrtypes", {}).get(obj.get("rrtype"))
        if rrspec is None:
            codes.append("rrtype_not_allowed")

    operation = obj.get("operation")
    if rrspec is not None and operation not in rrspec.get("operations", []):
        codes.append("operation_not_allowed")

    rdata = obj.get("rdata")
    ttl = obj.get("ttl")
    if not isinstance(rdata, list) or not all(isinstance(r, str) for r in rdata):
        codes.append("rdata_invalid")
        rdata = None
    if rdata is not None and policy.get("require_unique_rdata") and len(set(rdata)) != len(rdata):
        codes.append("rdata_not_unique")

    addrs = None
    if rdata is not None:
        addrs = []
        for r in rdata:
            try:
                addrs.append(ipaddress.ip_address(r))
            except ValueError:
                codes.append("rdata_invalid")
                addrs = None
                break

    if rrspec is not None and rdata is not None:
        if operation == "add":
            if not rdata:
                codes.append("rdata_empty")
            if addrs is not None:
                nets = [ipaddress.ip_network(c) for c in rrspec.get("rdata_cidrs", [])]
                if any(not any(a in n for n in nets) for a in addrs):
                    codes.append("rdata_out_of_cidr")
            if not _is_int(ttl) or not (rrspec["ttl_min"] <= ttl <= rrspec["ttl_max"]):
                codes.append("ttl_out_of_range")
        elif operation == "delete":
            if rdata:
                codes.append("delete_payload")
            if ttl != 0 or not _is_int(ttl):
                codes.append("delete_ttl")

    prereq = obj.get("prerequisites")
    if not isinstance(prereq, dict):
        codes.append("prerequisites_invalid")
    else:
        want_keys = sorted(policy.get("prerequisite_keys", []))
        if sorted(prereq.keys()) != want_keys:
            codes.append("prerequisite_keys")
        if "host" in prereq and prereq["host"] != owner:
            codes.append("prerequisite_host")
        if zone is not None and "serial" in prereq:
            serial = prereq["serial"]
            if not _is_int(serial) or not (zone["serial_min"] <= serial <= zone["serial_max"]):
                codes.append("prerequisite_serial")

    iat = obj.get("iat")
    if not _is_int(iat):
        codes.append("iat_invalid")
    else:
        if iat - now_unix > policy.get("clock_skew_seconds", 0):
            codes.append("iat_skew")
        if now_unix - iat > policy.get("max_age_seconds", 0):
            codes.append("iat_stale")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        codes.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        codes.append("replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "owner": owner}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "owner": owner}
