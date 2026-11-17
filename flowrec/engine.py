from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

_SIGNED_FIELDS = (
    "kid",
    "exporter",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packets",
    "bytes",
    "start_time",
    "end_time",
    "iat",
    "nonce",
)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _signing_line(obj: dict) -> str:
    return "v1|" + "|".join(str(obj[name]) for name in _SIGNED_FIELDS)


def _ip_contained(value: Any, cidrs: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not isinstance(cidrs, list):
        return False
    for cidr in cidrs:
        if not isinstance(cidr, str):
            continue
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if network.version != address.version:
            continue
        if address in network:
            return True
    return False


def inspect_flow(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "exporter": obj.get("exporter"),
        "src_ip": obj.get("src_ip"),
        "dst_ip": obj.get("dst_ip"),
        "src_port": obj.get("src_port"),
        "dst_port": obj.get("dst_port"),
        "protocol": obj.get("protocol"),
        "packets": obj.get("packets"),
        "bytes": obj.get("bytes"),
        "start_time": obj.get("start_time"),
        "end_time": obj.get("end_time"),
        "nonce": obj.get("nonce"),
    }


def admit_flow(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []
    exporter_name = obj.get("exporter")

    required = _SIGNED_FIELDS + ("sig",)
    shape_ready = all(obj.get(name) is not None for name in required)
    if not shape_ready:
        reasons.append("missing_field")

    keyring = keys.get("keys", {}) if isinstance(keys, dict) else {}
    kid = obj.get("kid")
    key_entry = keyring.get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        reasons.append("unknown_key")
    elif key_entry.get("status") != "active":
        reasons.append("key_revoked")

    if key_entry is not None and key_entry.get("status") == "active" and shape_ready:
        try:
            key_material = bytes.fromhex(str(key_entry.get("secret", "")))
            digest = hmac.new(
                key_material,
                _signing_line(obj).encode("utf-8"),
                hashlib.sha256,
            ).digest()
            expected = _b64url(digest)
            given = obj.get("sig")
            if not isinstance(given, str) or not hmac.compare_digest(expected, given):
                reasons.append("bad_signature")
        except (ValueError, TypeError):
            reasons.append("bad_signature")

    exporters = policy.get("exporters", {}) if isinstance(policy, dict) else {}
    exporter = exporters.get(exporter_name) if isinstance(exporter_name, str) else None
    if exporter is None:
        reasons.append("exporter_unknown")

    if exporter is not None:
        if not _ip_contained(obj.get("src_ip"), exporter.get("src_cidrs")):
            reasons.append("src_network")
        if not _ip_contained(obj.get("dst_ip"), exporter.get("dst_cidrs")):
            reasons.append("dst_network")

        port_min = policy.get("port_min")
        port_max = policy.get("port_max")
        src_port = obj.get("src_port")
        dst_port = obj.get("dst_port")
        if not _is_int(src_port) or not (
            _is_int(port_min) and _is_int(port_max) and port_min <= src_port <= port_max
        ):
            reasons.append("src_port")
        if not _is_int(dst_port) or not (
            _is_int(port_min) and _is_int(port_max) and port_min <= dst_port <= port_max
        ):
            reasons.append("dst_port")

        protocol = obj.get("protocol")
        if protocol not in exporter.get("protocols", []):
            reasons.append("protocol_denied")
        elif not _is_int(dst_port) or dst_port not in exporter.get("dst_ports", {}).get(protocol, []):
            reasons.append("dst_port_protocol")

        packets = obj.get("packets")
        byte_count = obj.get("bytes")
        if not _is_int(packets) or not (
            exporter.get("packets_min") <= packets <= exporter.get("packets_max")
        ):
            reasons.append("packets_range")
        if not _is_int(byte_count) or not (
            exporter.get("bytes_min") <= byte_count <= exporter.get("bytes_max")
        ):
            reasons.append("bytes_range")
        if (
            _is_int(packets)
            and _is_int(byte_count)
            and byte_count < packets * exporter.get("min_bytes_per_packet", 0)
        ):
            reasons.append("byte_packet_ratio")

        start_time = obj.get("start_time")
        end_time = obj.get("end_time")
        start_time_min = policy.get("start_time_min")
        if not _is_int(start_time) or not (
            _is_int(start_time_min) and start_time >= start_time_min
        ):
            reasons.append("start_time_range")
        if not _is_int(start_time) or not _is_int(end_time) or end_time < start_time:
            reasons.append("time_order")
        if (
            _is_int(start_time)
            and _is_int(end_time)
            and end_time - start_time > exporter.get("duration_max", 0)
        ):
            reasons.append("duration_exceeded")

    iat = obj.get("iat")
    if not _is_int(iat):
        reasons.append("iat_window")
    else:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if not (now_unix - max_age <= iat <= now_unix + skew):
            reasons.append("iat_window")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("nonce_invalid")
    elif nonce in store.get("items", {}):
        reasons.append("replay")

    if reasons:
        return {
            "decision": "deny",
            "reason_codes": list(dict.fromkeys(reasons)),
            "exporter": exporter_name,
        }

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "exporter": exporter_name}
