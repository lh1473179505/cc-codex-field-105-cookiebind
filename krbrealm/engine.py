from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
from typing import Any

SIGNING_VERSION = "v1"

def inspect_ticket(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "realm": obj.get("realm"),
        "spn": obj.get("spn"),
        "enctypes": obj.get("enctypes"),
        "pac": obj.get("pac"),
        "client": obj.get("client"),
        "addresses": obj.get("addresses"),
        "nonce": obj.get("nonce"),
    }


def _signing_line(obj: dict) -> str:
    return "|".join([
        SIGNING_VERSION,
        str(obj["kid"]),
        str(obj["realm"]),
        str(obj["spn"]),
        ",".join(obj["enctypes"]),
        str(obj["pac"]),
        str(obj["client"]),
        ",".join(obj["addresses"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ])


def _verify_signature(obj: dict, keys: dict, reasons: list) -> None:
    entry = keys.get("keys", {}).get(obj.get("kid"))
    if not isinstance(entry, dict):
        reasons.append("unknown_key")
        return
    if entry.get("status") != "active":
        reasons.append("key_revoked")
    try:
        secret = bytes.fromhex(entry["secret"])
        expected = base64.urlsafe_b64encode(
            hmac.new(secret, _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
        ).rstrip(b"=").decode("ascii")
    except (KeyError, TypeError, ValueError):
        reasons.append("bad_signature")
        return
    if not hmac.compare_digest(expected, str(obj.get("sig", ""))):
        reasons.append("bad_signature")


def _check_spn(obj: dict, realm_policy: dict | None, reasons: list) -> None:
    spn = obj.get("spn")
    if not isinstance(spn, str) or spn.count("@") != 1 or spn.count("/") < 1:
        reasons.append("bad_spn")
        return
    service_host, spn_realm = spn.rsplit("@", 1)
    service, sep, host = service_host.partition("/")
    if not sep or not service or not host or not spn_realm or "/" in host:
        reasons.append("bad_spn")
        return
    if spn_realm != obj.get("realm"):
        reasons.append("spn_realm_mismatch")
    if realm_policy is None:
        return
    if service not in realm_policy.get("services", []):
        reasons.append("bad_service")
    suffixes = realm_policy.get("host_suffixes", [])
    if not any(host.endswith(suffix) and len(host) > len(suffix) for suffix in suffixes):
        reasons.append("bad_host_suffix")


def _check_enctypes(obj: dict, realm_policy: dict, reasons: list) -> None:
    enctypes = obj.get("enctypes")
    if not isinstance(enctypes, list) or not enctypes or not all(isinstance(e, str) for e in enctypes):
        reasons.append("bad_enctype")
        return
    allowed = set(realm_policy.get("enctypes", []))
    if not set(enctypes).issubset(allowed):
        reasons.append("bad_enctype")
    required = realm_policy.get("required_enctype")
    if required is not None and required not in enctypes:
        reasons.append("missing_required_enctype")


def _check_client(obj: dict, realm_policy: dict, reasons: list) -> None:
    client = obj.get("client")
    prefixes = realm_policy.get("client_prefixes", [])
    if not isinstance(client, str) or not any(client.startswith(prefix) for prefix in prefixes):
        reasons.append("bad_client")


def _check_addresses(obj: dict, policy: dict, realm_policy: dict, reasons: list) -> None:
    raw = obj.get("addresses")
    if not isinstance(raw, list) or not raw or not all(isinstance(a, str) for a in raw):
        reasons.append("bad_address_count")
        return
    try:
        addresses = [ipaddress.ip_address(item) for item in raw]
    except ValueError:
        reasons.append("bad_address_syntax")
        return
    if policy.get("forbid_duplicate_addresses", False) and len(set(addresses)) != len(addresses):
        reasons.append("duplicate_address")
    if not 1 <= len(addresses) <= policy.get("max_addresses", len(addresses)):
        reasons.append("bad_address_count")
    networks = []
    for cidr in realm_policy.get("client_cidrs", []):
        try:
            networks.append(ipaddress.ip_network(cidr))
        except ValueError:
            continue
    for address in addresses:
        if not any(address.version == network.version and address in network for network in networks):
            reasons.append("address_outside_cidr")
            break


def _check_iat(obj: dict, policy: dict, now_unix: int, reasons: list) -> None:
    iat = obj.get("iat")
    if not isinstance(iat, int) or isinstance(iat, bool):
        reasons.append("bad_iat")
        return
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if iat > now_unix + skew:
        reasons.append("iat_in_future")
    elif iat < now_unix - max_age - skew:
        reasons.append("iat_expired")


def admit_ticket(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []

    realm = obj.get("realm")
    realm_policy = policy.get("realms", {}).get(realm) if isinstance(realm, str) else None
    if realm_policy is None:
        reasons.append("unknown_realm")

    _check_spn(obj, realm_policy, reasons)
    if realm_policy is not None:
        _check_enctypes(obj, realm_policy, reasons)
        _check_client(obj, realm_policy, reasons)
        _check_addresses(obj, policy, realm_policy, reasons)

    if policy.get("require_pac", False) and obj.get("pac") != 1:
        reasons.append("pac_required")

    _check_iat(obj, policy, now_unix, reasons)
    _verify_signature(obj, keys, reasons)

    nonce = obj.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        reasons.append("bad_nonce")
    elif nonce in store.get("items", {}):
        reasons.append("nonce_replay")

    if reasons:
        return {"decision": "deny", "reason_codes": reasons, "spn": obj.get("spn")}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "spn": obj.get("spn")}
