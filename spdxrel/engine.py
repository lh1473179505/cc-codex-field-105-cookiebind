from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_relationship(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "document_namespace": obj.get("document_namespace"),
        "spdx_id": obj.get("spdx_id"),
        "related_spdx_id": obj.get("related_spdx_id"),
        "relationship_type": obj.get("relationship_type"),
        "license": obj.get("license"),
        "file_sha256": obj.get("file_sha256"),
        "nonce": obj.get("nonce"),
    }

def _signing_line(obj: dict) -> str:
    return "v1|{kid}|{document_namespace}|{spdx_id}|{related_spdx_id}|{relationship_type}|{license}|{file_sha256}|{iat}|{nonce}".format(
        kid=obj.get("kid"),
        document_namespace=obj.get("document_namespace"),
        spdx_id=obj.get("spdx_id"),
        related_spdx_id=obj.get("related_spdx_id"),
        relationship_type=obj.get("relationship_type"),
        license=obj.get("license"),
        file_sha256=obj.get("file_sha256"),
        iat=obj.get("iat"),
        nonce=obj.get("nonce"),
    )

def _expected_sig(secret_hex: str, line: str) -> str:
    digest = hmac.new(bytes.fromhex(secret_hex), line.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def admit_relationship(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    reasons: list[str] = []

    def deny(code: str) -> dict:
        return {"decision": "deny", "reason_codes": [code], "spdx_id": obj.get("spdx_id")}

    documents = policy.get("documents", {})
    document = documents.get(obj.get("document_namespace"))
    if document is None:
        return deny("unknown_document")

    pattern = policy.get("spdx_id_pattern", r"^SPDXRef-[A-Za-z0-9][A-Za-z0-9.-]*$")
    spdx_id = obj.get("spdx_id")
    related_spdx_id = obj.get("related_spdx_id")
    if not isinstance(spdx_id, str) or not re.fullmatch(pattern, spdx_id):
        return deny("spdx_id_syntax")
    if not isinstance(related_spdx_id, str) or not re.fullmatch(pattern, related_spdx_id):
        return deny("spdx_id_syntax")

    elements = document.get("elements", {})
    if spdx_id not in elements:
        return deny("unknown_source_element")
    target = elements.get(related_spdx_id)
    if target is None:
        return deny("unknown_target_element")

    if spdx_id == related_spdx_id:
        return deny("self_relationship")

    relationship_type = obj.get("relationship_type")
    targets = document.get("relationships", {}).get(spdx_id, {}).get(relationship_type, [])
    if related_spdx_id not in targets:
        return deny("relationship_not_registered")

    if obj.get("license") != target.get("license"):
        return deny("license_mismatch")

    file_sha256 = obj.get("file_sha256")
    hex_len = policy.get("sha256_hex_len", 64)
    if target.get("kind") == "File":
        if (
            not isinstance(file_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{%d}" % hex_len, file_sha256)
            or file_sha256 != target.get("sha256")
        ):
            return deny("file_sha256_mismatch")
    else:
        if file_sha256 != "":
            return deny("file_sha256_forbidden")

    key = keys.get("keys", {}).get(obj.get("kid"))
    if key is None:
        return deny("unknown_key")
    if key.get("status") != "active":
        return deny("key_revoked")

    expected = _expected_sig(key.get("secret", ""), _signing_line(obj))
    if not hmac.compare_digest(expected, str(obj.get("sig"))):
        return deny("bad_signature")

    iat = obj.get("iat")
    if not isinstance(iat, int):
        return deny("iat_invalid")
    max_age = policy.get("max_age_seconds", 600)
    skew = policy.get("clock_skew_seconds", 60)
    if now_unix - iat > max_age:
        return deny("iat_expired")
    if iat - now_unix > skew:
        return deny("iat_future")

    nonce = obj.get("nonce")
    items = store.setdefault("items", {})
    if nonce in items:
        return deny("replay")

    items[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": reasons, "spdx_id": spdx_id}
