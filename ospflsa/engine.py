from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_ipv4(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(ipaddress.IPv4Address(value)) == value
    except ValueError:
        return False


def _lsid_in_cidrs(lsid: str, cidrs: list) -> bool:
    try:
        address = ipaddress.IPv4Address(lsid)
        networks = [ipaddress.IPv4Network(cidr, strict=True) for cidr in cidrs]
    except ValueError:
        return False
    return any(address in network for network in networks)


def _signing_string(obj: dict) -> str:
    return "v1|{kid}|{area}|{router_id}|{lsa_type}|{lsid}|{age}|{sequence}|{payload_sha256}|{iat}|{nonce}".format(
        kid=obj["kid"],
        area=obj["area"],
        router_id=obj["router_id"],
        lsa_type=obj["lsa_type"],
        lsid=obj["lsid"],
        age=obj["age"],
        sequence=obj["sequence"],
        payload_sha256=obj["payload_sha256"],
        iat=obj["iat"],
        nonce=obj["nonce"],
    )


def _expected_signature(secret: str, signing_string: str) -> str:
    digest = hmac.new(bytes.fromhex(secret), signing_string.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def inspect_lsa(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "area": obj.get("area"),
        "router_id": obj.get("router_id"),
        "lsa_type": obj.get("lsa_type"),
        "lsid": obj.get("lsid"),
        "age": obj.get("age"),
        "sequence": obj.get("sequence"),
        "payload_sha256": obj.get("payload_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_lsa(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reason_codes: list[str] = []

    required = (
        "kid", "area", "router_id", "lsa_type", "lsid", "age",
        "sequence", "payload_sha256", "nonce", "iat", "sig",
    )
    if not isinstance(obj, dict) or any(field not in obj for field in required):
        return {"decision": "deny", "reason_codes": ["malformed_lsa"], "lsid": obj.get("lsid") if isinstance(obj, dict) else None}

    if not _is_int(obj["age"]) or not _is_int(obj["sequence"]) or not _is_int(obj["iat"]):
        reason_codes.append("malformed_field")

    area = policy.get("areas", {}).get(obj["area"]) if _is_ipv4(obj["area"]) else None
    if area is None:
        reason_codes.append("unknown_area")

    router = area.get("routers", {}).get(obj["router_id"]) if area is not None and _is_ipv4(obj["router_id"]) else None
    if area is not None and router is None:
        reason_codes.append("unknown_router")

    type_conf = router.get("types", {}).get(obj["lsa_type"]) if router is not None and isinstance(obj["lsa_type"], str) else None
    if router is not None and type_conf is None:
        reason_codes.append("unknown_type")

    if type_conf is not None and not _is_ipv4(obj["lsid"]):
        reason_codes.append("malformed_lsid")
    if type_conf is not None and _is_ipv4(obj["lsid"]):
        if not _lsid_in_cidrs(obj["lsid"], type_conf.get("lsid_cidrs", [])):
            reason_codes.append("lsid_outside_cidr")
        if obj["lsa_type"] == "router" and policy.get("require_router_lsid_identity") and obj["lsid"] != obj["router_id"]:
            reason_codes.append("router_lsid_identity")

    if _is_int(obj["age"]) and area is not None:
        if not area["age_min"] <= obj["age"] <= area["age_max"]:
            reason_codes.append("age_out_of_range")

    if _is_int(obj["sequence"]) and router is not None:
        if not router["sequence_min"] <= obj["sequence"] <= router["sequence_max"]:
            reason_codes.append("sequence_out_of_range")

    digest = obj["payload_sha256"]
    hex_len = policy.get("payload_sha256_hex_len", 64)
    hex_chars = "0123456789abcdef" if policy.get("require_lowercase_hex", True) else "0123456789abcdefABCDEF"
    valid_hex = (
        isinstance(digest, str)
        and len(digest) == hex_len
        and all(char in hex_chars for char in digest)
    )
    if not valid_hex:
        reason_codes.append("payload_digest_invalid")

    key_conf = keys.get("keys", {}).get(obj["kid"])
    if key_conf is None:
        reason_codes.append("unknown_key")
    elif key_conf.get("status") != "active":
        reason_codes.append("key_revoked")
    else:
        try:
            expected = _expected_signature(key_conf["secret"], _signing_string(obj))
        except (ValueError, KeyError):
            expected = None
        if expected is None or not isinstance(obj["sig"], str) or not hmac.compare_digest(expected, obj["sig"]):
            reason_codes.append("bad_signature")

    if _is_int(obj["iat"]):
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if not now_unix - max_age <= obj["iat"] <= now_unix + skew:
            reason_codes.append("iat_out_of_window")

    if not isinstance(obj["nonce"], str) or not obj["nonce"]:
        reason_codes.append("malformed_nonce")
    else:
        items = store.get("items")
        if isinstance(items, dict) and obj["nonce"] in items:
            reason_codes.append("nonce_replay")
        elif not isinstance(items, dict):
            reason_codes.append("malformed_store")

    if reason_codes:
        return {"decision": "deny", "reason_codes": reason_codes, "lsid": obj["lsid"]}

    store.setdefault("items", {})[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "lsid": obj["lsid"]}
