from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

def inspect_peer(peer: dict) -> dict:
    return {
        "kid": peer.get("kid"),
        "pubkey": peer.get("pubkey"),
        "endpoint_host": peer.get("endpoint_host"),
        "endpoint_ip": peer.get("endpoint_ip"),
        "allowed_ips": peer.get("allowed_ips"),
        "keepalive": peer.get("keepalive"),
        "nonce": peer.get("nonce"),
    }


def _deny(pubkey: Any, reason_code: str) -> dict:
    return {"decision": "deny", "reason_codes": [reason_code], "pubkey": pubkey}


def _signing_input(peer: dict) -> bytes:
    fields = [
        "v1",
        str(peer.get("kid")),
        str(peer.get("pubkey")),
        str(peer.get("endpoint_host")),
        str(peer.get("endpoint_ip")),
        ",".join(peer.get("allowed_ips", [])),
        str(peer.get("keepalive")),
        str(peer.get("psk_hash")),
        str(peer.get("iat")),
        str(peer.get("nonce")),
    ]
    return "|".join(fields).encode("utf-8")


def _expected_signature(secret_hex: str, message: bytes) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), message, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _is_default_route(network: ipaddress._BaseNetwork) -> bool:
    return network.prefixlen == 0


def admit_peer(peer: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    pubkey = peer.get("pubkey")

    # Gate 1: HMAC signature and kid revocation.
    key_entry = keys.get("keys", {}).get(peer.get("kid"))
    if not isinstance(key_entry, dict) or "secret" not in key_entry:
        return _deny(pubkey, "unknown_kid")
    if key_entry.get("status") != "active":
        return _deny(pubkey, "kid_revoked")
    message = _signing_input(peer)
    try:
        expected = _expected_signature(key_entry["secret"], message)
    except ValueError:
        return _deny(pubkey, "bad_signature")
    if not hmac.compare_digest(expected, str(peer.get("sig", ""))):
        return _deny(pubkey, "bad_signature")

    # Gate 2: pubkey registration and endpoint host suffix.
    peers = policy.get("peers", {})
    peer_entry = peers.get(pubkey)
    if not isinstance(peer_entry, dict):
        return _deny(pubkey, "unknown_pubkey")
    if not str(peer.get("endpoint_host", "")).endswith(peer_entry.get("endpoint_suffix", "")):
        return _deny(pubkey, "bad_endpoint_suffix")

    # Gate 3: endpoint_ip must belong to one of endpoint_ip_cidrs.
    endpoint_ip = ipaddress.ip_address(peer.get("endpoint_ip"))
    endpoint_cidrs = [ipaddress.ip_network(c) for c in policy.get("endpoint_ip_cidrs", [])]
    if not any(endpoint_ip in cidr and endpoint_ip.version == cidr.version for cidr in endpoint_cidrs):
        return _deny(pubkey, "bad_endpoint_ip")

    # Gate 4: every allowed_ip must sit inside the peer pool, and none may
    # overlap a denied CIDR or claim a default route.
    pool = ipaddress.ip_network(peer_entry["pool"])
    denied = [ipaddress.ip_network(c) for c in policy.get("denied_cidrs", [])]
    allowed_nets = [ipaddress.ip_network(raw) for raw in peer.get("allowed_ips", [])]
    for allowed in allowed_nets:
        if _is_default_route(allowed):
            return _deny(pubkey, "default_route")
        for blocked in denied:
            if allowed.version != blocked.version or _is_default_route(blocked):
                continue
            if allowed == blocked or allowed.subnet_of(blocked) or blocked.subnet_of(allowed):
                return _deny(pubkey, "denied_cidr")
    for allowed in allowed_nets:
        if allowed.version != pool.version or not allowed.subnet_of(pool):
            return _deny(pubkey, "outside_pool")

    # Gate 5: keepalive interval.
    keepalive = peer.get("keepalive")
    if not isinstance(keepalive, int) or isinstance(keepalive, bool):
        return _deny(pubkey, "bad_keepalive")
    if not policy.get("keepalive_min", 0) <= keepalive <= policy.get("keepalive_max", 0):
        return _deny(pubkey, "bad_keepalive")

    # Gate 6: PSK binding when the peer requires it.
    if peer_entry.get("require_psk"):
        required_psk = policy.get("psk_hashes", {}).get(pubkey)
        if not required_psk or not hmac.compare_digest(str(required_psk), str(peer.get("psk_hash", ""))):
            return _deny(pubkey, "bad_psk")

    # Gate 7: freshness window, then replay (nonce is allow-only state).
    iat = peer.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return _deny(pubkey, "iat_out_of_window")
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if iat > now_unix + skew or now_unix - iat > max_age:
        return _deny(pubkey, "iat_out_of_window")
    nonce = str(peer.get("nonce", ""))
    if nonce in store.setdefault("items", {}):
        return _deny(pubkey, "nonce_replay")

    store["items"][nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "pubkey": pubkey}
