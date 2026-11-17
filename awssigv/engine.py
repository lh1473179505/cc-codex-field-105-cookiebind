from __future__ import annotations
import base64
import hashlib
import hmac
import re

def inspect_request(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "service": obj.get("service"),
        "region": obj.get("region"),
        "method": obj.get("method"),
        "canonical_path": obj.get("canonical_path"),
        "canonical_query": obj.get("canonical_query"),
        "signed_headers": obj.get("signed_headers"),
        "payload_sha256": obj.get("payload_sha256"),
        "nonce": obj.get("nonce"),
    }

_LOWERCASE_HEX64 = re.compile(r"^[0-9a-f]{64}$")

def _canonical_query(canonical_query: dict) -> str:
    return ",".join(f"{key}={value}" for key, value in sorted(canonical_query.items()))

def _signing_line(obj: dict) -> str:
    canonical_query = _canonical_query(obj["canonical_query"])
    signed_headers = ",".join(obj["signed_headers"])
    return "|".join([
        "v1",
        str(obj["kid"]),
        str(obj["service"]),
        str(obj["region"]),
        str(obj["method"]),
        str(obj["canonical_path"]),
        canonical_query,
        signed_headers,
        str(obj["payload_sha256"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ])

def _expected_signature(secret_hex: str, signing_line: str) -> str:
    digest = hmac.new(
        bytes.fromhex(secret_hex),
        signing_line.encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _path_is_safe(canonical_path: str, deny_substrings: list) -> bool:
    if not isinstance(canonical_path, str) or not canonical_path.startswith("/"):
        return False
    for needle in deny_substrings:
        if needle and needle in canonical_path:
            return False
    components = canonical_path.split("/")
    for component in components[1:-1]:
        if component in (".", ".."):
            return False
        if component == "":
            return False
    return True

def admit_request(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    service_name = obj.get("service")
    deny: list[str] = []

    required_fields = (
        "kid", "service", "region", "method", "canonical_path",
        "canonical_query", "signed_headers", "payload_sha256", "nonce", "iat", "sig",
    )
    if any(not isinstance(obj.get(field), expected) for field, expected in (
        ("kid", str), ("service", str), ("region", str), ("method", str),
        ("canonical_path", str), ("payload_sha256", str), ("nonce", str), ("sig", str),
    )) or not isinstance(obj.get("canonical_query"), dict) \
            or not isinstance(obj.get("signed_headers"), list) \
            or not isinstance(obj.get("iat"), int) \
            or any(field not in obj for field in required_fields):
        return {"decision": "deny", "reason_codes": ["malformed_request"], "service": service_name}

    key_entries = keys.get("keys", {})
    key_entry = key_entries.get(obj["kid"])
    if key_entry is None:
        deny.append("unknown_kid")
    elif key_entry.get("status") != "active":
        deny.append("key_revoked" if key_entry.get("status") == "revoked" else "key_inactive")

    service = policy.get("services", {}).get(obj["service"])
    if service is None:
        deny.append("service_not_allowed")
    else:
        if obj["region"] not in service.get("regions", []):
            deny.append("region_not_allowed")
        if obj["method"] not in service.get("methods", []):
            deny.append("method_not_allowed")

        if not _path_is_safe(obj["canonical_path"], policy.get("path_deny_substrings", [])):
            deny.append("path_invalid")
        elif not any(
            obj["canonical_path"] == prefix or obj["canonical_path"].startswith(prefix)
            for prefix in service.get("path_prefixes", [])
        ):
            deny.append("path_prefix_denied")

        canonical_query = obj["canonical_query"]
        query_allowed = set(service.get("query_allowed", []))
        query_required = service.get("query_required", {})
        if any(key not in query_allowed for key in canonical_query):
            deny.append("query_key_not_allowed")
        if any(
            key not in canonical_query or canonical_query[key] != value
            for key, value in query_required.items()
        ):
            deny.append("query_required_missing")

        signed_headers = obj["signed_headers"]
        headers_allowed = set(service.get("headers_allowed", []))
        headers_required = set(service.get("headers_required", []))
        header_set = set(signed_headers)
        if any(not isinstance(header, str) for header in signed_headers):
            deny.append("header_invalid")
        else:
            if len(signed_headers) != len(header_set) or signed_headers != sorted(header_set) \
                    or any(header != header.lower() for header in signed_headers):
                deny.append("header_order_invalid")
            if not headers_required.issubset(header_set):
                deny.append("header_required_missing")
            if not header_set.issubset(headers_allowed):
                deny.append("header_not_allowed")

    payload_sha256 = obj["payload_sha256"]
    if not _LOWERCASE_HEX64.fullmatch(payload_sha256):
        deny.append("payload_hash_format")
    if obj["method"] in policy.get("empty_payload_methods", []) \
            and payload_sha256 != policy.get("empty_payload_sha256"):
        deny.append("payload_method_mismatch")

    if key_entry is not None and isinstance(key_entry.get("secret"), str):
        signing_line = _signing_line(obj)
        try:
            expected = _expected_signature(key_entry["secret"], signing_line)
        except ValueError:
            expected = ""
        if not hmac.compare_digest(expected, obj["sig"]):
            deny.append("bad_signature")

    iat = obj["iat"]
    if iat < now_unix - int(policy.get("max_age_seconds", 0)):
        deny.append("iat_expired")
    if iat > now_unix + int(policy.get("clock_skew_seconds", 0)):
        deny.append("iat_future_skew")

    items = store.setdefault("items", {})
    if obj["nonce"] in items:
        deny.append("nonce_replay")

    if deny:
        return {"decision": "deny", "reason_codes": deny, "service": service_name}

    items[obj["nonce"]] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "service": service_name}
