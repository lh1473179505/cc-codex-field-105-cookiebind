from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
import re

_STRING_FIELDS = (
    "kid",
    "username",
    "common_name",
    "client_cidr",
    "route_cidr",
    "config_sha256",
    "nonce",
    "sig",
)
_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _report(username, decision, reason_codes):
    return {
        "decision": decision,
        "reason_codes": reason_codes,
        "username": username,
    }


def _deny(username, reason_code):
    return _report(username, "deny", [reason_code])


def _allow(username):
    return _report(username, "allow", [])


def _is_well_formed(obj):
    if not isinstance(obj, dict):
        return False
    for field in _STRING_FIELDS:
        value = obj.get(field)
        if not isinstance(value, str) or not value:
            return False
    dns_domains = obj.get("dns_domains")
    if not isinstance(dns_domains, list) or not all(
        isinstance(name, str) and name for name in dns_domains
    ):
        return False
    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        return False
    return True


def _signing_message(obj):
    return "|".join(
        (
            "v1",
            obj["kid"],
            obj["username"],
            obj["common_name"],
            obj["client_cidr"],
            obj["route_cidr"],
            ",".join(obj["dns_domains"]),
            obj["config_sha256"],
            str(obj["iat"]),
            obj["nonce"],
        )
    )


def _expected_signature(secret_hex, message):
    secret = bytes.fromhex(secret_hex)
    digest = hmac.new(secret, message.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _parse_strict_network(text):
    try:
        network = ipaddress.ip_network(text, strict=True)
    except ValueError:
        return None
    if str(network) != text:
        return None
    return network


def _is_contained(network, supernet_texts):
    for text in supernet_texts:
        try:
            supernet = ipaddress.ip_network(text, strict=True)
        except ValueError:
            continue
        if network.version == supernet.version and network.subnet_of(supernet):
            return True
    return False


def _is_valid_domain(name):
    if not name or len(name) > 253:
        return False
    if name != name.lower():
        return False
    labels = name.split(".")
    return all(re.fullmatch(_DOMAIN_LABEL_RE, label) for label in labels)


def _domain_matches_suffix(name, suffixes):
    return any(name == suffix or name.endswith("." + suffix) for suffix in suffixes)


def _digest_matches_policy(digest, policy):
    length = int(policy.get("config_sha256_hex_len", 64))
    if policy.get("require_lowercase_hex", True):
        return re.fullmatch(r"[0-9a-f]{%d}" % length, digest) is not None
    return re.fullmatch(r"[0-9a-fA-F]{%d}" % length, digest) is not None


def inspect_push(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "username": obj.get("username"),
        "common_name": obj.get("common_name"),
        "client_cidr": obj.get("client_cidr"),
        "route_cidr": obj.get("route_cidr"),
        "dns_domains": obj.get("dns_domains"),
        "config_sha256": obj.get("config_sha256"),
        "nonce": obj.get("nonce"),
    }

def admit_push(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    username = obj.get("username") if isinstance(obj, dict) else None
    if not _is_well_formed(obj):
        return _deny(username, "malformed_push")

    keyring = keys.get("keys") if isinstance(keys, dict) else None
    key = keyring.get(obj["kid"]) if isinstance(keyring, dict) else None
    if not isinstance(key, dict) or not isinstance(key.get("secret"), str):
        return _deny(username, "bad_sig")
    try:
        expected_sig = _expected_signature(key["secret"], _signing_message(obj))
    except ValueError:
        return _deny(username, "bad_sig")
    if not hmac.compare_digest(expected_sig, obj["sig"]):
        return _deny(username, "bad_sig")

    if key.get("status") != "active":
        return _deny(username, "revoked_key")

    iat = obj["iat"]
    skew = int(policy.get("clock_skew_seconds", 0))
    max_age = int(policy.get("max_age_seconds", 0))
    if iat < now_unix - max_age:
        return _deny(username, "iat_expired")
    if iat > now_unix + skew:
        return _deny(username, "iat_too_new")

    users = policy.get("users", {})
    user_policy = users.get(obj["username"]) if isinstance(users, dict) else None
    if not isinstance(user_policy, dict):
        return _deny(username, "unknown_user")

    if obj["common_name"] not in user_policy.get("common_names", []):
        return _deny(username, "common_name_mismatch")

    client_net = _parse_strict_network(obj["client_cidr"])
    if client_net is None:
        return _deny(username, "client_cidr_not_canonical")
    if policy.get("forbid_default_route", False) and client_net.prefixlen == 0:
        return _deny(username, "default_route_forbidden")
    if not _is_contained(client_net, user_policy.get("client_supernets", [])):
        return _deny(username, "client_cidr_unauthorized")

    route_net = _parse_strict_network(obj["route_cidr"])
    if route_net is None:
        return _deny(username, "route_cidr_not_canonical")
    if policy.get("forbid_default_route", False) and route_net.prefixlen == 0:
        return _deny(username, "default_route_forbidden")
    if not _is_contained(route_net, user_policy.get("route_supernets", [])):
        return _deny(username, "route_cidr_unauthorized")

    dns_domains = obj["dns_domains"]
    max_dns = int(user_policy.get("max_dns_domains", 0))
    if len(dns_domains) < 1:
        return _deny(username, "dns_empty")
    if len(dns_domains) > max_dns:
        return _deny(username, "dns_count_exceeded")
    if policy.get("require_unique_dns", False) and len(set(dns_domains)) != len(dns_domains):
        return _deny(username, "dns_duplicate")
    suffixes = user_policy.get("dns_suffixes", [])
    for name in dns_domains:
        if not _is_valid_domain(name):
            return _deny(username, "dns_invalid_name")
        if not _domain_matches_suffix(name, suffixes):
            return _deny(username, "dns_suffix_unauthorized")
    for required in user_policy.get("dns_required", []):
        if required not in dns_domains:
            return _deny(username, "dns_required_missing")

    if not _digest_matches_policy(obj["config_sha256"], policy):
        return _deny(username, "config_digest_invalid")

    items = store.get("items") if isinstance(store, dict) else None
    if isinstance(items, dict) and obj["nonce"] in items:
        return _deny(username, "nonce_replay")

    if not isinstance(items, dict):
        items = {}
        store["items"] = items
    items[obj["nonce"]] = {"ts": now_unix}
    return _allow(username)
