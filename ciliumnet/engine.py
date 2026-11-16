from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

def inspect_pol(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "endpoint": obj.get("endpoint"),
        "direction": obj.get("direction"),
        "cidr": obj.get("cidr"),
        "port": obj.get("port"),
        "proto": obj.get("proto"),
        "nonce": obj.get("nonce"),
    }


def admit_pol(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    report: dict[str, Any] = {
        "decision": "deny",
        "reason_codes": [],
        "endpoint": obj.get("endpoint"),
    }

    required = ("kid", "endpoint", "direction", "cidr", "port", "proto", "iat", "nonce", "sig")
    if any(obj.get(field) is None for field in required):
        report["reason_codes"].append("malformed")
        return report

    key_entry = keys.get("keys", {}).get(obj["kid"])
    if key_entry is None:
        report["reason_codes"].append("unknown_kid")
        return report
    if key_entry.get("status") != "active":
        report["reason_codes"].append("key_revoked")
        return report

    signing_line = "|".join(
        [
            "v1",
            str(obj["kid"]),
            str(obj["endpoint"]),
            str(obj["direction"]),
            str(obj["cidr"]),
            str(obj["port"]),
            str(obj["proto"]),
            str(obj["iat"]),
            str(obj["nonce"]),
        ]
    )
    digest = hmac.new(
        bytes.fromhex(key_entry["secret"]),
        signing_line.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    expected_sig = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    if not hmac.compare_digest(expected_sig, str(obj["sig"])):
        report["reason_codes"].append("bad_signature")
        return report

    endpoints = policy.get("endpoints", {})
    ep_cfg = endpoints.get(obj["endpoint"])
    if not isinstance(ep_cfg, dict):
        report["reason_codes"].append("unknown_endpoint")
        return report

    direction = obj["direction"]
    if direction not in ("egress", "ingress"):
        report["reason_codes"].append("bad_direction")
        return report

    try:
        req_net = ipaddress.ip_network(obj["cidr"], strict=False)
    except ValueError:
        report["reason_codes"].append("bad_cidr")
        return report

    if req_net == ipaddress.ip_network("0.0.0.0/0") or req_net == ipaddress.ip_network("::/0"):
        report["reason_codes"].append("default_route")
        return report

    for denied in policy.get("denied_cidrs", []):
        denied_net = ipaddress.ip_network(denied, strict=False)
        if denied_net.version != req_net.version:
            continue
        if denied_net.prefixlen == 0:
            continue
        if req_net.subnet_of(denied_net):
            report["reason_codes"].append("cidr_denied")
            return report

    direction_cidrs = ep_cfg.get("egress_cidrs" if direction == "egress" else "ingress_cidrs", [])
    contained = False
    for allowed in direction_cidrs:
        allowed_net = ipaddress.ip_network(allowed, strict=False)
        if allowed_net.version != req_net.version:
            continue
        if req_net.subnet_of(allowed_net):
            contained = True
            break
    if not contained:
        report["reason_codes"].append("cidr_not_allowed")
        return report

    if obj["port"] not in ep_cfg.get("ports", []):
        report["reason_codes"].append("port_not_allowed")
        return report

    if obj["proto"] not in ep_cfg.get("protos", []):
        report["reason_codes"].append("proto_not_allowed")
        return report

    clock_skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    iat = obj["iat"]
    if not isinstance(iat, int) or iat > now_unix + clock_skew or now_unix - iat > max_age + clock_skew:
        report["reason_codes"].append("iat_out_of_window")
        return report

    nonce = str(obj["nonce"])
    items = store.setdefault("items", {})
    if nonce in items:
        report["reason_codes"].append("replay")
        return report

    items[nonce] = {"ts": now_unix}
    report["decision"] = "allow"
    return report
