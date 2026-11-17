from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
import re
from typing import Any

_NAME_RE = re.compile(r"[a-z][a-z0-9_-]*\Z")
_DNS_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _signing_line(obj: dict) -> str:
    return (
        "v1|{kid}|{name}|{jid}|{hostname}|{ip4}|{path}|{securelevel}|{iat}|{nonce}".format(
            kid=obj["kid"],
            name=obj["name"],
            jid=obj["jid"],
            hostname=obj["hostname"],
            ip4=obj["ip4"],
            path=obj["path"],
            securelevel=obj["securelevel"],
            iat=obj["iat"],
            nonce=obj["nonce"],
        )
    )


def _expected_signature(obj: dict, secret_hex: str) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        _signing_line(obj).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return _b64url(digest)


def _parse_ipv4(text: Any):
    if not isinstance(text, str):
        return None
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.version != 4:
        return None
    return address


def _is_lowercase_dns(name: Any) -> bool:
    if not isinstance(name, str) or not name or name != name.lower():
        return False
    return all(re.fullmatch(_DNS_LABEL_RE, label) for label in name.split("."))


def _path_is_canonical(path: Any, deny_substrings: list) -> bool:
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    if any(sub in path for sub in deny_substrings):
        return False
    return all(component not in ("", ".", "..") for component in path.split("/")[1:])


def inspect_jail(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "name": obj.get("name"),
        "jid": obj.get("jid"),
        "hostname": obj.get("hostname"),
        "ip4": obj.get("ip4"),
        "path": obj.get("path"),
        "securelevel": obj.get("securelevel"),
        "nonce": obj.get("nonce"),
    }


def admit_jail(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    name = obj.get("name") if isinstance(obj, dict) else None

    def deny(code: str) -> dict:
        return {"decision": "deny", "reason_codes": [code], "name": name}

    if not isinstance(obj, dict):
        return deny("shape")

    # Gate 1: name syntax is checked before any policy lookup.
    name_max_len = policy.get("name_max_len", 32)
    if (
        not isinstance(name, str)
        or not name
        or len(name) > name_max_len
        or _NAME_RE.fullmatch(name) is None
    ):
        return deny("name_syntax")

    # Gate 2: select the jail bound to that exact name.
    jail = policy.get("jails", {}).get(name)
    if not isinstance(jail, dict):
        return deny("name_unknown")

    # Gate 3: jid is an integer inside the global range and bound to the jail.
    jid = obj.get("jid")
    if not _is_int(jid) or not (
        policy.get("jid_min", 1) <= jid <= policy.get("jid_max", 999999)
    ):
        return deny("jid_range")
    if jid != jail.get("jid"):
        return deny("jid_binding")

    # Gate 4: hostname is an exact lowercase DNS name of the selected jail.
    hostname = obj.get("hostname")
    if not _is_lowercase_dns(hostname) or hostname != jail.get("hostname"):
        return deny("hostname")

    # Gate 5: ip4 is a real IPv4 address: parse it, reject forbidden/special
    # addresses, then require membership in one of the jail's networks using
    # numeric address math rather than string prefixes.
    ip4 = _parse_ipv4(obj.get("ip4"))
    if ip4 is None:
        return deny("ip4_syntax")
    forbidden = []
    for entry in policy.get("forbidden_ip4", []):
        parsed = _parse_ipv4(entry)
        if parsed is not None:
            forbidden.append(parsed)
    if (
        ip4 in forbidden
        or ip4.is_multicast
        or ip4.is_loopback
        or ip4.is_unspecified
        or ip4.is_reserved
        or ip4.is_link_local
    ):
        return deny("ip4_forbidden")
    networks = []
    for entry in jail.get("ip4_networks", []):
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            networks.append(network)
    if not any(ip4 in network for network in networks):
        return deny("ip4_network")

    # Gate 6: path stays canonical (no traversal hiding behind normalization)
    # and is exactly the selected jail's root path.
    path = obj.get("path")
    deny_substrings = policy.get("path_deny_substrings", [])
    if not _path_is_canonical(path, deny_substrings):
        return deny("path_traversal")
    if path != jail.get("path"):
        return deny("path_binding")

    # Gate 7: securelevel is an integer inside the jail's inclusive window.
    securelevel = obj.get("securelevel")
    if not _is_int(securelevel) or not (
        jail.get("securelevel_min") <= securelevel <= jail.get("securelevel_max")
    ):
        return deny("securelevel")

    # Gate 8: the signing key must exist and be active; a revoked key denies
    # even when the HMAC itself verifies.
    kid = obj.get("kid")
    key_entry = keys.get("keys", {}).get(kid) if isinstance(kid, str) else None
    if key_entry is None:
        return deny("unknown_key")
    if key_entry.get("status") != "active":
        return deny("key_revoked")

    # Gate 9: recompute the complete v1 signing line and verify the HMAC.
    fields_ready = (
        isinstance(kid, str)
        and isinstance(name, str)
        and isinstance(hostname, str)
        and isinstance(obj.get("ip4"), str)
        and isinstance(path, str)
        and isinstance(obj.get("nonce"), str)
        and _is_int(jid)
        and _is_int(securelevel)
        and _is_int(obj.get("iat"))
    )
    if not fields_ready:
        return deny("bad_signature")
    try:
        expected = _expected_signature(obj, key_entry["secret"])
    except (ValueError, KeyError):
        return deny("bad_signature")
    if not hmac.compare_digest(expected, str(obj.get("sig", ""))):
        return deny("bad_signature")

    # Gate 10: iat must be no older than max_age and no more than skew ahead.
    iat = obj.get("iat")
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if iat > now_unix + skew or now_unix - iat > max_age:
        return deny("iat_window")

    # Gate 11: nonce replay protection; only an allow consumes the nonce.
    nonce = obj.get("nonce")
    items = store.get("items")
    if not isinstance(items, dict):
        return deny("store_shape")
    if nonce in items:
        return deny("nonce_replay")

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "name": name}
