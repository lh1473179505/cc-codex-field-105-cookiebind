from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

def inspect_option(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "subnet": obj.get("subnet"),
        "option_code": obj.get("option_code"),
        "value_type": obj.get("value_type"),
        "value": obj.get("value"),
        "pool_start": obj.get("pool_start"),
        "pool_end": obj.get("pool_end"),
        "nonce": obj.get("nonce"),
    }

def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)

def _mac_string(obj: dict) -> str:
    return "v1|{kid}|{subnet}|{option_code}|{value_type}|{value}|{pool_start}|{pool_end}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        subnet=obj.get("subnet"),
        option_code=obj.get("option_code"),
        value_type=obj.get("value_type"),
        value=obj.get("value"),
        pool_start=obj.get("pool_start"),
        pool_end=obj.get("pool_end"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, mac: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), mac.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _parse_ipv4(value: Any):
    if not isinstance(value, str):
        return None
    try:
        return ipaddress.IPv4Address(value)
    except ValueError:
        return None

def _in_any_cidr(addr, cidrs) -> bool:
    for cidr in cidrs or []:
        try:
            net = ipaddress.ip_network(cidr, strict=True)
        except ValueError:
            continue
        if isinstance(net, ipaddress.IPv4Network) and addr in net:
            return True
    return False

def admit_option(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    subnet = obj.get("subnet")

    required_ok = (
        isinstance(subnet, str)
        and _is_int(obj.get("option_code"))
        and isinstance(obj.get("value_type"), str)
        and isinstance(obj.get("value"), str)
        and isinstance(obj.get("pool_start"), str)
        and isinstance(obj.get("pool_end"), str)
        and _is_int(obj.get("iat"))
        and isinstance(obj.get("nonce"), str)
        and isinstance(obj.get("kid"), str)
        and isinstance(obj.get("sig"), str)
    )
    if not required_ok:
        return {"decision": "deny", "reason_codes": ["malformed"], "subnet": subnet}

    network = None
    subnet_entry = None
    try:
        network = ipaddress.ip_network(subnet, strict=True)
        if not isinstance(network, ipaddress.IPv4Network):
            network = None
            reasons.append("subnet_invalid")
    except ValueError:
        try:
            ipaddress.ip_network(subnet, strict=False)
            reasons.append("subnet_host_bits")
        except ValueError:
            reasons.append("subnet_invalid")
    if network is not None:
        subnets = policy.get("subnets") or {}
        subnet_entry = subnets.get(str(network))
        if subnet_entry is None:
            reasons.append("subnet_unknown")

    if subnet_entry is not None:
        code = obj["option_code"]
        forbidden = subnet_entry.get("forbidden_options") or []
        options = subnet_entry.get("options") or {}
        option_def = options.get(str(code))
        if code in forbidden:
            reasons.append("option_forbidden")
        elif option_def is None:
            reasons.append("option_unknown")
        else:
            if obj["value_type"] != option_def.get("value_type"):
                reasons.append("value_type")
            elif option_def.get("value_type") == "ipv4":
                addr = _parse_ipv4(obj["value"])
                if addr is None:
                    reasons.append("value_syntax")
                elif not _in_any_cidr(addr, option_def.get("value_cidrs")):
                    reasons.append("value_cidr")

        pool_start = _parse_ipv4(obj["pool_start"])
        pool_end = _parse_ipv4(obj["pool_end"])
        pool_cidrs = subnet_entry.get("pool_cidrs")
        if pool_start is None or pool_start not in network or not _in_any_cidr(pool_start, pool_cidrs):
            reasons.append("pool_start")
        if pool_end is None or pool_end not in network or not _in_any_cidr(pool_end, pool_cidrs):
            reasons.append("pool_end")
        if pool_start is not None and pool_end is not None and int(pool_start) > int(pool_end):
            reasons.append("pool_order")

    key_entry = (keys.get("keys") or {}).get(obj["kid"])
    if key_entry is None:
        reasons.append("key_unknown")
    else:
        if key_entry.get("status") != "active":
            reasons.append("revoked")
        try:
            expected = _expected_sig(key_entry.get("secret", ""), _mac_string(obj))
        except (ValueError, TypeError):
            expected = None
        if expected is None or not hmac.compare_digest(expected, obj["sig"]):
            reasons.append("bad_sig")

    iat = obj["iat"]
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if iat - now_unix > skew:
        reasons.append("iat_future")
    elif now_unix - iat > max_age:
        reasons.append("iat_stale")

    items = store.get("items") or {}
    if obj["nonce"] in items:
        reasons.append("replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "subnet": subnet}

    items[obj["nonce"]] = {"ts": now_unix}
    store["items"] = items
    return {"decision": "allow", "reason_codes": [], "subnet": subnet}
