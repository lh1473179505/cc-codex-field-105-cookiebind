from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import re

SIGNATURE_VERSION = "v1"
_LOWER_HEX = re.compile(r"^[0-9a-f]+$")

def inspect_binding(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "peer": obj.get("peer"),
        "lsr_id": obj.get("lsr_id"),
        "fec": obj.get("fec"),
        "transport_address": obj.get("transport_address"),
        "label": obj.get("label"),
        "binding_sha256": obj.get("binding_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_binding(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    fec = obj.get("fec")

    def deny(code: str) -> dict:
        return {"decision": "deny", "reason_codes": [code], "fec": fec}

    peer_entry = policy.get("peers", {}).get(obj.get("peer"))
    if peer_entry is None:
        return deny("unknown_peer")

    if obj.get("lsr_id") != peer_entry.get("lsr_id"):
        return deny("lsr_id_mismatch")

    try:
        fec_network = ipaddress.ip_network(str(fec), strict=True)
    except ValueError:
        return deny("fec_not_canonical")

    if policy.get("forbid_default_fec", True) and fec_network.prefixlen == 0:
        return deny("fec_default_forbidden")

    if not any(
        fec_network.version == ipaddress.ip_network(supernet).version
        and fec_network.subnet_of(ipaddress.ip_network(supernet))
        for supernet in peer_entry.get("fec_supernets", [])
    ):
        return deny("fec_not_contained")

    try:
        transport = ipaddress.ip_address(str(obj.get("transport_address")))
    except ValueError:
        return deny("transport_not_address")

    if not any(
        transport.version == ipaddress.ip_network(cidr).version
        and transport in ipaddress.ip_network(cidr)
        for cidr in peer_entry.get("transport_cidrs", [])
    ):
        return deny("transport_not_in_cidr")

    if policy.get("transport_must_equal_peer", False):
        try:
            peer_address = ipaddress.ip_address(str(obj.get("peer")))
        except ValueError:
            peer_address = None
        if peer_address is None or transport != peer_address:
            return deny("transport_not_peer")

    label = obj.get("label")
    if not isinstance(label, int) or isinstance(label, bool) or not (
        peer_entry["label_min"] <= label <= peer_entry["label_max"]
    ):
        return deny("label_out_of_range")

    if label in peer_entry.get("reserved_labels", []):
        return deny("label_reserved")

    digest = obj.get("binding_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != policy.get("binding_sha256_hex_len", 64)
        or not _LOWER_HEX.match(digest)
    ):
        return deny("binding_digest_invalid")

    key_entry = keys.get("keys", {}).get(obj.get("kid"))
    if key_entry is None:
        return deny("unknown_kid")
    if key_entry.get("status") != "active":
        return deny("key_revoked")

    message = "|".join(
        [
            SIGNATURE_VERSION,
            str(obj.get("kid")),
            str(obj.get("peer")),
            str(obj.get("lsr_id")),
            str(fec),
            str(obj.get("transport_address")),
            str(label),
            digest,
            str(obj.get("iat")),
            str(obj.get("nonce")),
        ]
    ).encode("utf-8")
    expected = base64.urlsafe_b64encode(
        hmac.new(bytes.fromhex(key_entry["secret"]), message, hashlib.sha256).digest()
    ).rstrip(b"=")
    if not hmac.compare_digest(expected, str(obj.get("sig", "")).encode("utf-8")):
        return deny("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return deny("iat_invalid")
    age = now_unix - iat
    if age > policy.get("max_age_seconds", 600):
        return deny("iat_stale")
    if age < -policy.get("clock_skew_seconds", 60):
        return deny("iat_future")

    nonce = obj.get("nonce")
    if nonce in store.get("items", {}):
        return deny("nonce_replayed")

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "fec": fec}
