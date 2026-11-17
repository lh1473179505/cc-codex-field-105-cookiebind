from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
import re
from typing import Any

_COMMUNITY_RE = re.compile(r"^\d+:\d+$")


def inspect_route(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "peer": obj.get("peer"),
        "as_path": obj.get("as_path"),
        "origin": obj.get("origin"),
        "prefix": obj.get("prefix"),
        "next_hop": obj.get("next_hop"),
        "communities": obj.get("communities"),
        "nonce": obj.get("nonce"),
    }


def _b64url(digest: bytes) -> str:
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _signed_line(obj: dict) -> str:
    as_path = ",".join(str(asn) for asn in obj["as_path"])
    communities = ",".join(obj["communities"])
    return "|".join((
        "v1",
        str(obj["kid"]),
        str(obj["peer"]),
        as_path,
        str(obj["origin"]),
        str(obj["prefix"]),
        str(obj["next_hop"]),
        communities,
        str(obj["iat"]),
        str(obj["nonce"]),
    ))


def _deny(prefix: Any, codes: list[str]) -> dict:
    return {"decision": "deny", "reason_codes": codes, "prefix": prefix}


def admit_route(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    prefix_value = obj.get("prefix")
    codes: list[str] = []

    key_entries = keys.get("keys", {})
    kid = obj.get("kid")
    key_entry = key_entries.get(kid) if isinstance(kid, str) else None
    if not isinstance(key_entry, dict) or key_entry.get("status") != "active":
        codes.append("key_inactive")

    peer_value = obj.get("peer")
    peer_policy = policy.get("peers", {}).get(peer_value) if isinstance(peer_value, str) else None
    if peer_policy is None:
        codes.append("unknown_peer")

    as_path = obj.get("as_path")
    path_ok = (
        isinstance(as_path, list)
        and len(as_path) > 0
        and all(isinstance(asn, int) and not isinstance(asn, bool) for asn in as_path)
    )
    if not path_ok:
        codes.append("bad_as_path")

    communities = obj.get("communities")
    communities_ok = isinstance(communities, list) and all(
        isinstance(community, str) for community in communities
    )
    if not communities_ok:
        codes.append("bad_communities")

    iat = obj.get("iat")
    iat_ok = isinstance(iat, int) and not isinstance(iat, bool)
    if not iat_ok:
        codes.append("bad_iat")

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        codes.append("bad_nonce")

    if not codes and key_entry is not None:
        secret = key_entry.get("secret", "")
        try:
            secret_bytes = bytes.fromhex(secret)
        except (TypeError, ValueError):
            secret_bytes = b""
        digest = hmac.new(
            secret_bytes, _signed_line(obj).encode("utf-8"), hashlib.sha256
        ).digest()
        supplied = obj.get("sig")
        if not isinstance(supplied, str) or not hmac.compare_digest(_b64url(digest), supplied):
            codes.append("bad_signature")

    if iat_ok:
        skew = policy.get("clock_skew_seconds", 0)
        max_age = policy.get("max_age_seconds", 0)
        if iat < now_unix - max_age or iat > now_unix + skew:
            codes.append("iat_outside_window")

    if path_ok and peer_policy is not None:
        if policy.get("require_peer_as_first", True) and as_path[0] != peer_policy.get("asn"):
            codes.append("peer_as_path_mismatch")
        if len(as_path) > peer_policy.get("as_path_max", len(as_path)):
            codes.append("as_path_too_long")
        if policy.get("forbid_local_as_loop", True) and policy.get("local_as") in as_path:
            codes.append("local_as_loop")

    origin = obj.get("origin")
    if peer_policy is not None and origin not in peer_policy.get("origins", []):
        codes.append("origin_not_allowed")

    parsed_prefix = None
    try:
        if not isinstance(prefix_value, str):
            raise ValueError
        parsed_prefix = ipaddress.ip_network(prefix_value, strict=True)
    except (ValueError, TypeError):
        codes.append("bad_prefix")

    if parsed_prefix is not None:
        if policy.get("forbid_default_route", True) and parsed_prefix.prefixlen == 0:
            codes.append("default_route")
        if peer_policy is not None:
            contained = any(
                parsed_prefix.version == ipaddress.ip_network(supernet).version
                and parsed_prefix.subnet_of(ipaddress.ip_network(supernet))
                for supernet in peer_policy.get("prefix_supernets", [])
            )
            if not contained:
                codes.append("prefix_not_contained")

    next_hop = obj.get("next_hop")
    parsed_next_hop = None
    try:
        if not isinstance(next_hop, str):
            raise ValueError
        parsed_next_hop = ipaddress.ip_address(next_hop)
    except (ValueError, TypeError):
        codes.append("bad_next_hop")

    if parsed_next_hop is not None and peer_policy is not None:
        hop_ok = any(
            parsed_next_hop.version == ipaddress.ip_network(cidr).version
            and parsed_next_hop in ipaddress.ip_network(cidr)
            for cidr in peer_policy.get("next_hop_cidrs", [])
        )
        if not hop_ok:
            codes.append("next_hop_not_allowed")

    if communities_ok and peer_policy is not None:
        allowed = set(peer_policy.get("communities_allowed", []))
        required = peer_policy.get("communities_required", [])
        if not all(re.fullmatch(_COMMUNITY_RE, community) for community in communities):
            codes.append("bad_community_format")
        if policy.get("require_unique_communities", True) and len(set(communities)) != len(communities):
            codes.append("duplicate_community")
        if any(community not in allowed for community in communities):
            codes.append("community_not_allowed")
        if any(community not in communities for community in required):
            codes.append("community_required_missing")

    if isinstance(nonce, str) and nonce and nonce in store.get("items", {}):
        codes.append("replay")

    if codes:
        return _deny(prefix_value, codes)

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "prefix": prefix_value}
