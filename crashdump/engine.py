from __future__ import annotations
import base64
import hashlib
import hmac
import re
from typing import Any

def inspect_dump(obj: dict) -> dict:
    return {
        "kid": obj.get("kid"),
        "product": obj.get("product"),
        "build_id": obj.get("build_id"),
        "arch": obj.get("arch"),
        "pc_address": obj.get("pc_address"),
        "module_offset": obj.get("module_offset"),
        "dump_sha256": obj.get("dump_sha256"),
        "size_bytes": obj.get("size_bytes"),
        "nonce": obj.get("nonce"),
    }

def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def _signing_line(obj: dict) -> str:
    return "|".join([
        "v1",
        str(obj["kid"]),
        str(obj["product"]),
        str(obj["build_id"]),
        str(obj["arch"]),
        str(obj["pc_address"]),
        str(obj["module_offset"]),
        str(obj["dump_sha256"]),
        str(obj["size_bytes"]),
        str(obj["iat"]),
        str(obj["nonce"]),
    ])

def _resolve_path(obj: dict, policy: dict, codes: list[str]) -> tuple[dict | None, dict | None]:
    products = policy.get("products") or {}
    product = obj.get("product")
    product_entry = products.get(product) if isinstance(product, str) else None
    if product_entry is None:
        codes.append("unknown_product")
        return None, None

    build_id = obj.get("build_id")
    build_entry = (product_entry.get("builds") or {}).get(build_id) if isinstance(build_id, str) else None
    if build_entry is None:
        codes.append("unknown_build")
        return None, None

    arch = obj.get("arch")
    arch_entry = (build_entry.get("arches") or {}).get(arch) if isinstance(arch, str) else None
    if arch_entry is None:
        codes.append("unknown_arch")
        return build_entry, None

    return build_entry, arch_entry

def _check_pc_and_module(obj: dict, arch_entry: dict, policy: dict, codes: list[str]) -> None:
    digits = policy.get("pc_hex_digits", 0)
    pc_address = obj.get("pc_address")
    pc_match = (
        isinstance(pc_address, str)
        and re.fullmatch(r"0x[0-9a-f]{" + str(digits) + r"}", pc_address) is not None
    )
    if not pc_match:
        codes.append("pc_format")

    offset = obj.get("module_offset")
    module_base = arch_entry.get("module_base", 0)
    module_size = arch_entry.get("module_size", 0)
    offset_in_range = _is_int(offset) and 0 <= offset < module_size
    if not offset_in_range:
        codes.append("module_range")

    if pc_match and offset_in_range and int(pc_address, 16) != module_base + offset:
        codes.append("pc_offset")

def _check_digest(obj: dict, policy: dict, codes: list[str]) -> None:
    digest = obj.get("dump_sha256")
    hex_len = policy.get("sha256_hex_len", 64)
    if not isinstance(digest, str) or len(digest) != hex_len:
        codes.append("digest_length")
        return
    if re.fullmatch(r"[0-9a-f]{" + str(hex_len) + r"}", digest) is None:
        codes.append("digest_case")

def _check_size(obj: dict, build_entry: dict, codes: list[str]) -> None:
    size_bytes = obj.get("size_bytes")
    size_min = build_entry.get("dump_size_min", 0)
    size_max = build_entry.get("dump_size_max", 0)
    if not _is_int(size_bytes) or not (size_min <= size_bytes <= size_max):
        codes.append("dump_size")

def _check_key_and_signature(obj: dict, keys: dict, codes: list[str]) -> None:
    kid = obj.get("kid")
    entry = (keys.get("keys") or {}).get(kid) if isinstance(kid, str) else None
    if entry is None:
        codes.append("unknown_key")
        return
    if entry.get("status") != "active":
        codes.append("key_revoked")

    fields_ready = (
        isinstance(obj.get("product"), str)
        and isinstance(obj.get("build_id"), str)
        and isinstance(obj.get("arch"), str)
        and isinstance(obj.get("pc_address"), str)
        and isinstance(obj.get("dump_sha256"), str)
        and isinstance(obj.get("nonce"), str)
        and _is_int(obj.get("module_offset"))
        and _is_int(obj.get("size_bytes"))
        and _is_int(obj.get("iat"))
    )
    if not fields_ready:
        codes.append("bad_signature")
        return
    expected = _b64url(
        hmac.new(bytes.fromhex(entry["secret"]), _signing_line(obj).encode("utf-8"), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(expected, str(obj.get("sig", ""))):
        codes.append("bad_signature")

def _check_iat(obj: dict, policy: dict, now_unix: int, codes: list[str]) -> None:
    iat = obj.get("iat")
    if not _is_int(iat):
        codes.append("iat_window")
        return
    skew = policy.get("clock_skew_seconds", 0)
    max_age = policy.get("max_age_seconds", 0)
    if not (now_unix - max_age - skew <= iat <= now_unix + skew):
        codes.append("iat_window")

def admit_dump(obj: dict, keys: dict, policy: dict, store: dict, now_unix: int) -> dict:
    codes: list[str] = []

    build_entry, arch_entry = _resolve_path(obj, policy, codes)
    if build_entry is not None:
        _check_size(obj, build_entry, codes)
    if arch_entry is not None:
        _check_pc_and_module(obj, arch_entry, policy, codes)
    _check_digest(obj, policy, codes)

    _check_key_and_signature(obj, keys, codes)
    _check_iat(obj, policy, now_unix, codes)

    nonce = obj.get("nonce")
    if isinstance(nonce, str) and nonce in (store.get("items") or {}):
        codes.append("nonce_replay")

    if codes:
        return {"decision": "deny", "reason_codes": codes, "product": obj.get("product")}

    store.setdefault("items", {})[nonce] = {"ts": now_unix}
    return {"decision": "allow", "reason_codes": [], "product": obj.get("product")}
